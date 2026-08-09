/**
 * DAE - Lectura de correo puzzle en custodia propia
 *
 * Aqui es donde la custodia propia deja de ser una promesa: la clave
 * privada NO esta en nuestros servidores, asi que el mensaje se descifra
 * en el navegador de quien lo recibe. Nosotros no podemos leerlo, y esto
 * es lo que hace que sea verdad y no una frase de marketing.
 *
 * Lo que hace, en orden:
 *
 *   1. Abre el fichero .daekey con la contrasena que pone el usuario.
 *      Es formato propio y simple —PBKDF2 + AES-256-GCM sobre un PKCS#8—
 *      porque WebCrypto no sabe abrir un PKCS#8 protegido: no implementa
 *      PBES2. Por eso el .pem de siempre no le sirve tal cual.
 *   2. Con esa clave abre una entrada de arrEncKeys del eHead y saca dos
 *      cosas: la clave AES del mensaje y el localizador de la otra pieza.
 *   3. Pide esa pieza a /ebody/<localizador>. Al servidor no le llega
 *      quien pregunta ni de que mensaje se trata: no puede saberlo.
 *   4. Junta las dos, descifra con AES-256-GCM y verifica el tag.
 *
 * La clave descifrada vive en memoria y solo mientras dura la pestanya.
 * No se guarda en localStorage ni en una cookie a proposito: lo que no
 * esta escrito no se lo lleva nadie.
 */

window.daeCrypto = (function () {
    'use strict';

    var objFirma = null;   // la misma clave, para firmar

    var objClave = null;      // CryptoKey en memoria, nada mas
    var szQuien  = '';

    function bytes(sz) {
        var arr = new Uint8Array(sz.length);
        for (var i = 0; i < sz.length; i++) { arr[i] = sz.charCodeAt(i) & 0xff; }
        return arr;
    }

    function deB64(sz) {
        return bytes(atob(String(sz).replace(/\s+/g, '')));
    }

    function hex(arrBytes) {
        var sz = '';
        for (var i = 0; i < arrBytes.length; i++) {
            sz += ('0' + arrBytes[i].toString(16)).slice(-2);
        }
        return sz;
    }

    /** ¿Hay una clave cargada en esta pestanya? */
    function lista() { return objClave !== null; }

    function duenyo() { return szQuien; }

    /**
     * Abre el .daekey y deja la clave lista para esta pestanya.
     *
     * @param {string} szJson  contenido del fichero
     * @param {string} szFrase contrasena que puso el usuario al exportar
     */
    async function cargar(szJson, szFrase) {
        var objSobre;
        try {
            objSobre = JSON.parse(szJson);
        } catch (e) {
            throw new Error('formato');
        }

        if (!objSobre || objSobre.szFormato !== 'DAE-KEY-1') {
            throw new Error('formato');
        }

        // PBKDF2 sobre la contrasena, con los parametros que vienen dentro
        var objBase = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(szFrase), 'PBKDF2', false, ['deriveKey']);

        var objEnvoltura = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: deB64(objSobre.szSalt),
                iterations: objSobre.nIter,
                hash: 'SHA-256'
            },
            objBase,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']);

        var arrPkcs8;
        try {
            arrPkcs8 = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: deB64(objSobre.szIv) },
                objEnvoltura,
                deB64(objSobre.szClave));
        } catch (e) {
            // El tag GCM no cuadra: la contrasena no es esa
            throw new Error('frase');
        }

        // SHA-1 no es un descuido: es lo que usa OpenSSL por defecto en
        // RSA-OAEP, y es con lo que se sellaron los mensajes. Cambiarlo
        // aqui haria ilegible todo el correo ya recibido.
        objClave = await crypto.subtle.importKey(
            'pkcs8', arrPkcs8,
            { name: 'RSA-OAEP', hash: 'SHA-1' },
            false, ['decrypt']);

        // La MISMA clave, importada otra vez para firmar. WebCrypto no
        // deja usar una clave de descifrar para firmar, y hace bien:
        // separar para que sirve cada clave evita ataques donde se hace
        // firmar algo a quien creia estar descifrando.
        //
        // PKCS#1 v1.5 con SHA-256, que es lo que hace openssl_sign en el
        // servidor. Si no coincidiera, el destinatario veria "firma no
        // valida" en un correo perfectamente legitimo, que asusta mas
        // que no firmarlo.
        try {
            objFirma = await crypto.subtle.importKey(
                'pkcs8', arrPkcs8,
                { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                false, ['sign']);
        } catch (e) {
            // Que no se pueda firmar no impide leer, que es a lo que se
            // vino. Se sigue sin firma y ya esta.
            objFirma = null;
        }

        szQuien = objSobre.szEmail || '';
        return szQuien;
    }

    /** Olvida la clave. Se llama al salir. */
    function olvidar() { objClave = null; objFirma = null; szQuien = ''; }

    /** True si la clave cargada puede ademas firmar. */
    function puedeFirmar() { return objFirma !== null; }

    /**
     * Firma unos bytes con la clave cargada.
     *
     * Devuelve la firma en crudo. Quien llama monta el sobre, porque el
     * formato del sobre es cosa del protocolo y no de la criptografia.
     */
    async function firmar(arrDatos) {
        if (!objFirma) { throw new Error('sin_clave_de_firma'); }
        return new Uint8Array(await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5' }, objFirma, arrDatos));
    }

    /**
     * Junta las dos piezas y devuelve el MIME en claro.
     *
     * @param {string} szHead  el eHead, tal cual llego (JSON)
     * @param {string} szBase  de donde bajar la segunda pieza
     */
    async function abrir(szHead, szBase) {
        if (!objClave) { throw new Error('sin_clave'); }

        var objHead;
        try {
            objHead = JSON.parse(szHead);
        } catch (e) {
            throw new Error('cabecera');
        }

        // Se prueban todas las entradas: un mensaje puede ir sellado para
        // varios destinatarios y solo una es la nuestra. Que fallen las
        // demas es lo normal.
        var arrAbierta = null;
        var arrEnc = objHead.arrEncKeys || {};
        for (var szHuella in arrEnc) {
            if (!Object.prototype.hasOwnProperty.call(arrEnc, szHuella)) { continue; }
            try {
                var arrCrudo = new Uint8Array(await crypto.subtle.decrypt(
                    { name: 'RSA-OAEP' }, objClave, deB64(arrEnc[szHuella])));
                if (arrCrudo.length === 64) { arrAbierta = arrCrudo; break; }
            } catch (e) { /* no era la nuestra */ }
        }

        if (!arrAbierta) { throw new Error('no_es_para_ti'); }

        var arrClaveAes = arrAbierta.slice(0, 32);
        var szLocaliza  = hex(arrAbierta.slice(32));

        // La segunda pieza. El localizador ES la credencial.
        var objResp = await fetch(szBase + '/ebody/' + szLocaliza, { credentials: 'omit' });
        if (!objResp.ok) {
            throw new Error(objResp.status === 404 ? 'pieza_no_esta' : 'pieza_error');
        }
        var arrBody = new Uint8Array(await objResp.arrayBuffer());

        // El cifrado completo: las dos piezas, sin el tag todavia.
        var arrPayload = deB64(objHead.szPayload);
        var arrTag     = deB64(objHead.szTag);
        var arrCifrado = new Uint8Array(arrPayload.length + arrBody.length);
        arrCifrado.set(arrPayload, 0);
        arrCifrado.set(arrBody, arrPayload.length);

        // TRANSFORMACION TODO-O-NADA (DAE-2). La llave que venia en la
        // cabecera no es la llave: viene enmascarada con el resumen del
        // cifrado ENTERO. Aqui se quita la mascara, y solo se puede
        // porque ya estan las dos piezas. Si faltase un byte saldria
        // otra llave y el descifrado de abajo fallaria, sin dejar leer
        // ni un trozo del mensaje.
        //
        // DAE-1 no lo llevaba y su llave va tal cual: hay correo viejo
        // repartido con ese formato y se sigue abriendo.
        if (objHead.szVersion === 'DAE-2') {
            var arrEtiqueta = new TextEncoder().encode('DAE-AONT-v2');
            var arrParaHash = new Uint8Array(arrEtiqueta.length + arrCifrado.length);
            arrParaHash.set(arrEtiqueta, 0);
            arrParaHash.set(arrCifrado, arrEtiqueta.length);

            var arrMascara = new Uint8Array(
                await crypto.subtle.digest('SHA-256', arrParaHash));
            for (var i = 0; i < arrClaveAes.length; i++) {
                arrClaveAes[i] ^= arrMascara[i];
            }
        }

        // Y ahora el tag pegado al final, como espera WebCrypto.
        var arrTodo = new Uint8Array(arrCifrado.length + arrTag.length);
        arrTodo.set(arrCifrado, 0);
        arrTodo.set(arrTag, arrCifrado.length);

        var objAes = await crypto.subtle.importKey(
            'raw', arrClaveAes, { name: 'AES-GCM' }, false, ['decrypt']);

        var arrClaro;
        try {
            arrClaro = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: deB64(objHead.szIv), tagLength: 128 },
                objAes, arrTodo);
        } catch (e) {
            // El tag no cuadra: las piezas estan alteradas o incompletas
            throw new Error('alterado');
        }

        return window.daeMime.texto(new Uint8Array(arrClaro));
    }

    return {
        cargar:      cargar,
        firmar:      firmar,
        puedeFirmar: puedeFirmar,
        abrir:    abrir,
        lista:    lista,
        duenyo:   duenyo,
        olvidar:  olvidar
    };
})();
