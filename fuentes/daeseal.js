/**
 * DAE - Sellar un correo puzzle EN EL NAVEGADOR
 *
 * Hasta ahora el bloque se construia en el servidor: clsAtAt llamaba a
 * clsEBlock::build() con el texto y los adjuntos en claro. Es decir, el
 * servidor veia el mensaje entero justo antes de cifrarlo. Aqui se hace
 * lo mismo en la maquina de quien escribe, y al servidor solo le llegan
 * las dos piezas ya cifradas.
 *
 * Gana el usuario, porque el mensaje no pasa en claro por nuestra parte,
 * y gana el servidor, que se quita de encima cifrar cada adjunto.
 *
 * DEBE PRODUCIR EXACTAMENTE LO MISMO QUE clsEBlock::build(). Si las dos
 * implementaciones se separan un byte, el correo se abre en una y no en
 * la otra. Hay prueba cruzada en tests/.
 *
 * LIMITE QUE NO SE OCULTA A NADIE: este fichero lo sirve nuestro
 * servidor. Un servidor comprometido podria mandar una version que se
 * chive. Esto reduce la exposicion diaria, NO elimina la confianza.
 * Quien no quiera confiar tiene dae_send.py y dae_open.py, que se leen
 * enteros y funcionan sin nosotros. Ver /?page=verificar.
 */
window.daeSeal = (function () {
    'use strict';

    var ETIQUETA_AONT = 'DAE-AONT-v2';
    var VERSION       = 'DAE-2';
    var ALGO          = 'A256GCM+RSA-OAEP+AONT';
    var MAX_HEAD      = 102400;   // 100 KB
    var RATIO_HEAD    = 0.10;     // 10 %

    function b64(arr) {
        var s = '';
        for (var i = 0; i < arr.length; i++) { s += String.fromCharCode(arr[i]); }
        return window.btoa(s);
    }

    function deB64(sz) {
        var s = window.atob(sz);
        var a = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) { a[i] = s.charCodeAt(i); }
        return a;
    }

    function hex(arr) {
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            s += ('0' + arr[i].toString(16)).slice(-2);
        }
        return s;
    }

    /** El cuerpo de un PEM, sin cabeceras ni saltos: los bytes DER. */
    function der(szPem) {
        return deB64(szPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
    }

    /**
     * La huella tiene que salir igual que en clsKeys::fingerprint():
     * SHA-256 en hexadecimal sobre los bytes DER de la clave publica.
     * Es la que indexa arrEncKeys, asi que si no coincide el
     * destinatario no encuentra su entrada.
     */
    async function huella(szPem) {
        return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', der(szPem))));
    }

    /**
     * RSA-OAEP con SHA-1, que es lo que usa OpenSSL por defecto y por
     * tanto lo que hay en todo el correo ya repartido. Cambiarlo aqui
     * dejaria los mensajes ilegibles para el resto del sistema.
     */
    async function importarPublica(szPem) {
        return crypto.subtle.importKey(
            'spki', der(szPem),
            { name: 'RSA-OAEP', hash: 'SHA-1' },
            false, ['encrypt']);
    }

    /**
     * Sella un mensaje para una o varias claves publicas.
     *
     * @param {Uint8Array} arrPlain  el MIME interior, ya montado
     * @param {string[]}   arrPems   claves publicas de los destinatarios
     * @returns {{szHead:string, arrBody:Uint8Array, szBodyId:string}}
     */
    async function sellar(arrPlain, arrPems) {
        if (!arrPlain || arrPlain.length === 0) { throw new Error('mensaje_vacio'); }
        if (!arrPems || arrPems.length === 0)   { throw new Error('sin_claves'); }

        // 1. clave y IV nuevos para ESTE mensaje y ninguno mas
        var arrKey = crypto.getRandomValues(new Uint8Array(32));
        var arrIv  = crypto.getRandomValues(new Uint8Array(12));

        var objAes = await crypto.subtle.importKey(
            'raw', arrKey, { name: 'AES-GCM' }, false, ['encrypt']);

        // 2. cifrar. WebCrypto devuelve el tag pegado al final; el resto
        //    del sistema los lleva separados, asi que se parten aqui.
        var arrConTag = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: arrIv, tagLength: 128 }, objAes, arrPlain));

        var arrCifrado = arrConTag.slice(0, arrConTag.length - 16);
        var arrTag     = arrConTag.slice(arrConTag.length - 16);

        // 3. TRANSFORMACION TODO-O-NADA. La clave no viaja: viaja
        //    enmascarada con el resumen del cifrado ENTERO, asi que para
        //    obtenerla hacen falta las dos piezas completas. A quien le
        //    falte un byte no le sale la clave, y sin clave no descifra
        //    ni un bit. Ver 06_AT_AT_PROTOCOL.md, seccion 3.bis.
        var arrEtiqueta = new TextEncoder().encode(ETIQUETA_AONT);
        var arrParaHash = new Uint8Array(arrEtiqueta.length + arrCifrado.length);
        arrParaHash.set(arrEtiqueta, 0);
        arrParaHash.set(arrCifrado, arrEtiqueta.length);

        var arrMascara = new Uint8Array(
            await crypto.subtle.digest('SHA-256', arrParaHash));

        var arrKeyOut = new Uint8Array(32);
        for (var i = 0; i < 32; i++) { arrKeyOut[i] = arrKey[i] ^ arrMascara[i]; }

        // 4. localizador opaco de la segunda pieza
        var arrBodyId = crypto.getRandomValues(new Uint8Array(32));
        var szBodyId  = hex(arrBodyId);

        // 5. una operacion RSA por destinatario. Cada una lleva la clave
        //    ENMASCARADA y el localizador: el localizador sale entero,
        //    porque hay que saber que pieza pedir antes de tenerla.
        var arrSemilla = new Uint8Array(64);
        arrSemilla.set(arrKeyOut, 0);
        arrSemilla.set(arrBodyId, 32);

        var objEncKeys = {};
        for (var j = 0; j < arrPems.length; j++) {
            var objPub = await importarPublica(arrPems[j]);
            var arrSellada = new Uint8Array(await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' }, objPub, arrSemilla));
            objEncKeys[await huella(arrPems[j])] = b64(arrSellada);
        }

        // 6. partir. SIEMPRE, y nunca el bloque entero en la cabecera.
        var nBlock = arrCifrado.length;
        var nHead  = Math.min(MAX_HEAD, Math.floor(nBlock * RATIO_HEAD));
        nHead = Math.max(1, Math.min(nHead, nBlock - 1));

        var arrPayload = arrCifrado.slice(0, nHead);
        var arrBody    = arrCifrado.slice(nHead);

        // El orden de las claves importa: el JSON tiene que salir igual
        // que el de PHP para que nada dependa de como lo serialice cada
        // uno. szChecksum NO va: era el valor que quita la mascara.
        var objHead = {
            szVersion:  VERSION,
            szAlgo:     ALGO,
            szIv:       b64(arrIv),
            szTag:      b64(arrTag),
            nBlockSize: nBlock,
            nHeadSize:  nHead,
            arrEncKeys: objEncKeys,
            szPayload:  b64(arrPayload)
        };

        return {
            szHead:   JSON.stringify(objHead),
            arrBody:  arrBody,
            szBodyId: szBodyId
        };
    }

    return {
        sellar:  sellar,
        huella:  huella,
        VERSION: VERSION
    };
})();
