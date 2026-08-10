/**
 * DAE - Seal a puzzle email IN THE BROWSER
 *
 * Until now the block was built on the server: clsAtAt called
 * clsEBlock::build() with the text and the attachments in the clear.
 * That is, the server saw the whole message right before encrypting it.
 * Here the same thing is done on the machine of whoever writes, and all
 * that reaches the server is the two already encrypted pieces.
 *
 * The user wins, because the message does not pass in the clear through
 * our side, and the server wins, as it gets rid of encrypting every
 * attachment.
 *
 * IT MUST PRODUCE EXACTLY THE SAME AS clsEBlock::build(). If the two
 * implementations drift apart by one byte, the mail opens in one and not
 * in the other. There is a cross test in tests/.
 *
 * Un solo formato, DAE-5, y a proposito. RSA y los formatos anteriores
 * se borraron enteros el 2026-08-10, con el sistema sin usuarios reales
 * y sin un correo repartido: sostener caminos de cifrado que no usaba
 * nadie era pagar para siempre por nada. Ver clsEBlock.php y
 * 06_AT_AT_PROTOCOL.md, secciones 3.ter, 3.quater y 3.quinquies.
 *
 * A LIMIT THAT IS HIDDEN FROM NOBODY: this file is served by our
 * server. A compromised server could send a version that snitches. This
 * reduces the daily exposure, it does NOT remove the trust. Whoever
 * does not want to trust has dae_send.py and dae_open.py, which can be
 * read end to end and work without us. See /?page=verificar.
 */
window.daeSeal = (function () {
    'use strict';

    var ETIQUETA_AONT = 'DAE-AONT-v2';
    var VERSION       = 'DAE-5';
    var ALGO          = 'A256GCM+X25519+AONT+PIN+ORIGIN';
    var MAX_HEAD      = 102400;   // 100 KB
    var RATIO_HEAD    = 0.10;     // 10 %

    /**
     * EL ORIGEN: el dominio donde va a quedar la segunda pieza.
     *
     * Hasta DAE-4 el sobre decia QUE pieza pedir y no decia DONDE vive,
     * asi que quien recibia de otro servidor la buscaba en su propia
     * casa y no estaba nunca. El correo puzzle entre dominios distintos
     * era imposible y no se noto porque solo habia un servidor.
     *
     * Va DENTRO del sobre, no en la cabecera: el eHead es un fichero que
     * se reenvia y se guarda, y suelto no puede ser un mapa hacia la
     * otra mitad. Formato, igual que en las otras cuatro
     * implementaciones:
     *
     *     k'(32) || localizador(32) || nLen(1) || origen(nLen)
     *
     * La longitud por delante y no un separador: un separador obliga a
     * decidir que pasa cuando aparece dentro del dato, y ahi es donde
     * cinco implementaciones empiezan a leer cosas distintas.
     */
    var ORIGEN_MAX = 253;   // maximo de un nombre de dominio, RFC 1035

    /**
     * El PIN va SIEMPRE, y cuando no hay segundo canal es este.
     *
     * 000000 NO PROTEGE DE NADA: es publico y esta escrito aqui. Sirve
     * para que haya UN solo camino de cifrado en lugar de dos, porque el
     * camino que se usa poco se prueba menos y acaba siendo el que falla.
     *
     * Regla que no se puede saltar: la pantalla NO puede decir
     * "protegido con PIN" cuando el PIN es este. Anunciar una proteccion
     * que no existe es peor que no tenerla, porque el usuario deja de
     * buscar otra.
     */
    var PIN_DEFECTO = '000000';

    /**
     * Derivacion del PIN: PBKDF2-SHA256, y no Argon2id.
     *
     * Argon2id seria mejor, porque resiste al hardware dedicado que es
     * justo lo que ataca un PIN corto. Pero WebCrypto NO LO TIENE, y
     * este fichero ES el navegador: con Argon2id no habria correo que
     * abrir. No se "mejora" esto sin cambiar antes las cinco
     * implementaciones a la vez.
     */
    var PIN_ITER = 600000;

    /**
     * Iteraciones cuando el PIN es el de por defecto.
     *
     * Con 000000 la derivacion lenta no compra NADA: el PIN es publico,
     * el atacante no tiene que probar nada. Gastar 600.000 iteraciones
     * ahi es un segundo largo por mensaje a cambio de cero, y ese es el
     * caso de casi todo el correo. El formato no cambia; cambia lo que
     * cuesta.
     */
    var PIN_ITER_DEFECTO = 1;

    /**
     * Etiqueta del HKDF. Ata la clave derivada a ESTE uso: si algun dia
     * se deriva otra cosa del mismo secreto compartido no saldra lo
     * mismo, y no se podran confundir las dos.
     */
    var INFO_KEK  = 'DAE-3-KEK';
    var LEN_PUB   = 32;
    var LEN_NONCE = 12;

    function b64(arr) {
        var s = '';
        for (var i = 0; i < arr.length; i++) { s += String.fromCharCode(arr[i]); }
        return window.btoa(s);
    }

    function hex(arr) {
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            s += ('0' + arr[i].toString(16)).slice(-2);
        }
        return s;
    }

    function unir(arrA, arrB) {
        var arrOut = new Uint8Array(arrA.length + arrB.length);
        arrOut.set(arrA, 0);
        arrOut.set(arrB, arrA.length);
        return arrOut;
    }

    /**
     * A ese nombre se le puede pedir la otra pieza?
     *
     * La regla es la de clsKeyFetch::dominioValido() y tiene que decir
     * lo mismo que ella: nombre de dominio publico con su punto, sin IP,
     * sin puerto, sin ruta, sin corchetes y sin los TLD reservados que
     * por definicion no son de nadie. Esta repetida aqui, y en
     * daecrypto.js, porque los dos ficheros se cargan por separado -la
     * pagina de leer un mensaje no trae este- y una dependencia entre
     * ellos dejaria media aplicacion sin validar.
     *
     * Al sellar sirve para cazar una configuracion mal escrita antes de
     * producir correo que no abre nadie. Al abrir (daecrypto.js) sirve
     * para algo mas serio, y alli esta explicado.
     */
    function dominioValido(szDominio) {
        szDominio = String(szDominio || '').trim().toLowerCase();

        if (szDominio === '' || szDominio.length > ORIGEN_MAX) { return false; }

        if (!/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/
                .test(szDominio)) {
            return false;
        }

        // Una IPv4 pasaria el patron de arriba. No vale: la pieza no se
        // le pide a un numero, se le pide a un nombre, que es lo unico
        // que un certificado puede acreditar.
        if (/^[0-9.]+$/.test(szDominio)) { return false; }

        var arrProhibidos = ['test', 'invalid', 'example', 'local',
                             'localhost', 'internal', 'home', 'lan'];
        var szTld = szDominio.split('.').pop();

        return arrProhibidos.indexOf(szTld) < 0;
    }

    /**
     * La huella que indexa arrEncKeys: SHA-256 en hexadecimal sobre los
     * 32 bytes crudos de la publica. Tiene que salir igual que en
     * clsCurve::fingerprint() o el destinatario no encuentra su entrada
     * y el correo le llega ilegible. Aqui no hay envoltura DER que
     * quitar, son 32 bytes y ya esta.
     *
     * @param {Uint8Array} arrPub  clave publica X25519, 32 bytes
     */
    async function huella(arrPub) {
        return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', arrPub)));
    }

    /**
     * Un par efimero, nuevo por destinatario.
     *
     * Nuevo por destinatario a proposito: con uno solo, dos
     * destinatarios del mismo correo podrian deducir que iba para ambos.
     *
     * Si el navegador no trae X25519 se para aqui y se dice. Buscar otro
     * camino seria fabricar un correo que no abre nadie, y eso es peor
     * que no enviarlo.
     */
    async function parEfimero() {
        try {
            return await crypto.subtle.generateKey(
                { name: 'X25519' }, false, ['deriveBits']);
        } catch (e) {
            throw new Error('sin_curva');
        }
    }

    /**
     * Envuelve una carga para el duenyo de arrDestPub.
     *
     * Sale eph_pub(32) || nonce(12) || cifrado+tag, byte a byte lo mismo
     * que clsCurve::wrap(). Es ECIES de manual: no hay crypto_box_seal
     * en WebCrypto, asi que se monta con las piezas que si estan en las
     * cinco implementaciones.
     *
     * @param {Uint8Array} arrCarga    lo que va dentro del sobre
     * @param {Uint8Array} arrDestPub  publica X25519 del destinatario
     * @returns {Uint8Array}
     */
    async function envolver(arrCarga, arrDestPub) {
        if (!arrDestPub || arrDestPub.length !== LEN_PUB) {
            throw new Error('clave_publica_mala');
        }

        var objDest = await crypto.subtle.importKey(
            'raw', arrDestPub, { name: 'X25519' }, false, []);

        var objEph    = await parEfimero();
        var arrEphPub = new Uint8Array(
            await crypto.subtle.exportKey('raw', objEph.publicKey));

        // El navegador aborta si el secreto compartido sale todo ceros,
        // que es lo que da una publica de orden pequenyo: un punto
        // elegido para que el resultado sea predecible. Se deja subir el
        // fallo en vez de cifrar con algo que el atacante ya conoce.
        var arrCompartido;
        try {
            arrCompartido = await crypto.subtle.deriveBits(
                { name: 'X25519', public: objDest }, objEph.privateKey, 256);
        } catch (e) {
            throw new Error('clave_publica_mala');
        }

        // La sal lleva las DOS publicas, la efimera y la del
        // destinatario. Sin eso el mismo secreto compartido daria la
        // misma KEK en contextos distintos, que es por donde se cuelan
        // las piezas reenviadas de un mensaje a otro.
        var objIkm = await crypto.subtle.importKey(
            'raw', arrCompartido, 'HKDF', false, ['deriveBits']);

        var arrKek = new Uint8Array(await crypto.subtle.deriveBits({
            name: 'HKDF',
            hash: 'SHA-256',
            salt: unir(arrEphPub, arrDestPub),
            info: new TextEncoder().encode(INFO_KEK)
        }, objIkm, 256));

        var objKek = await crypto.subtle.importKey(
            'raw', arrKek, { name: 'AES-GCM' }, false, ['encrypt']);

        var arrNonce = crypto.getRandomValues(new Uint8Array(LEN_NONCE));

        // WebCrypto deja el tag pegado al final, que es justo como viaja
        // el sobre. Aqui no hay que separarlo.
        var arrSellado = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: arrNonce, tagLength: 128 },
            objKek, arrCarga));

        return unir(unir(arrEphPub, arrNonce), arrSellado);
    }

    /**
     * La mascara que aporta el PIN.
     *
     * La sal son los 32 bytes CRUDOS del localizador, no su texto
     * hexadecimal: en PHP y en Python la sal es binaria, y aqui el
     * localizador nace ya como bytes. Pasar el hexadecimal daria una
     * mascara distinta y el correo no abriria en ningun otro sitio.
     *
     * Un PIN de seis cifras es un millon de combinaciones: nada, si se
     * pueden probar deprisa. Esto es lo que hace que probarlas cueste, y
     * solo aguanta acompanyado de las otras dos defensas: hay que tener
     * las dos piezas para empezar, y se cuentan los intentos de descarga
     * de la segunda.
     *
     * @param {string}     szPin  el PIN, tal cual lo escribe la persona
     * @param {Uint8Array} arrSal los 32 bytes del localizador
     * @param {number}     nIter  iteraciones, las que van en la cabecera
     * @returns {Uint8Array} 32 bytes
     */
    async function mascaraPin(szPin, arrSal, nIter) {
        var objBase = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(szPin), 'PBKDF2',
            false, ['deriveBits']);

        return new Uint8Array(await crypto.subtle.deriveBits({
            name: 'PBKDF2',
            salt: arrSal,
            iterations: nIter,
            hash: 'SHA-256'
        }, objBase, 256));
    }

    /**
     * Seals a message for one or several public keys.
     *
     * Las publicas llegan en crudo, 32 bytes cada una. No hay PEM que
     * parsear: el directorio publica hexadecimal y quien llama ya lo ha
     * pasado a bytes.
     *
     * El PIN es opcional porque casi nadie lo pone, no porque sea
     * opcional en el formato: si no llega, va el de por defecto y el
     * camino de cifrado es exactamente el mismo.
     *
     * El origen es OBLIGATORIO y no tiene valor por defecto. Aqui no se
     * puede adivinar: el navegador esta en la maquina de quien escribe,
     * y el dominio de la barra de direcciones no tiene por que ser
     * aquel donde va a quedar la pieza. Quien llama lo sabe -se lo dice
     * el servidor al que va a entregar- y tiene que decirlo. Ponerle un
     * valor por defecto seria sellar correo que no abre nadie el dia que
     * alguien monte esto en otro sitio.
     *
     * @param {Uint8Array}   arrPlain  the inner MIME, already assembled
     * @param {Uint8Array[]} arrPubs   X25519 keys of the recipients
     * @param {string}       [szPin]   el segundo canal, si lo hay
     * @param {string}       szOrigen  dominio donde quedara el eBody
     * @returns {{szHead:string, arrBody:Uint8Array, szBodyId:string}}
     */
    async function sellar(arrPlain, arrPubs, szPin, szOrigen) {
        if (!arrPlain || arrPlain.length === 0) { throw new Error('mensaje_vacio'); }
        if (!arrPubs || arrPubs.length === 0)   { throw new Error('sin_claves'); }

        szOrigen = String(szOrigen || '').trim().toLowerCase();
        if (!dominioValido(szOrigen)) { throw new Error('origen_malo'); }

        if (szPin === undefined || szPin === null || szPin === '') {
            szPin = PIN_DEFECTO;
        }

        // Cualquier cosa que no sean 32 bytes se rechaza aqui y no mas
        // adelante, donde el fallo saldria disfrazado de "no se ha
        // podido cifrar".
        for (var k = 0; k < arrPubs.length; k++) {
            if (!arrPubs[k] || arrPubs[k].length !== LEN_PUB) {
                throw new Error('clave_publica_mala');
            }
        }

        // 1. fresh key and IV for THIS message and no other one
        var arrKey = crypto.getRandomValues(new Uint8Array(32));
        var arrIv  = crypto.getRandomValues(new Uint8Array(12));

        var objAes = await crypto.subtle.importKey(
            'raw', arrKey, { name: 'AES-GCM' }, false, ['encrypt']);

        // 2. encrypt. WebCrypto returns the tag stuck at the end; the
        //    rest of the system carries them apart, so they split here.
        var arrConTag = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: arrIv, tagLength: 128 }, objAes, arrPlain));

        var arrCifrado = arrConTag.slice(0, arrConTag.length - 16);
        var arrTag     = arrConTag.slice(arrConTag.length - 16);

        // 3. ALL-OR-NOTHING TRANSFORM. The key does not travel: it
        //    travels masked with the digest of the WHOLE ciphertext, so
        //    getting it needs both pieces complete. Whoever is missing
        //    a byte does not get the key, and without the key they do
        //    not decrypt one bit. See 06_AT_AT_PROTOCOL.md, sec 3.bis.
        //
        //    Esto no cambia con la curva, y conviene decirlo: X25519 cae
        //    ante Shor igual que RSA. Lo que defiende del "copia hoy,
        //    descifra manyana" es esta transformacion, no el algoritmo.
        var arrEtiqueta = new TextEncoder().encode(ETIQUETA_AONT);
        var arrParaHash = new Uint8Array(arrEtiqueta.length + arrCifrado.length);
        arrParaHash.set(arrEtiqueta, 0);
        arrParaHash.set(arrCifrado, arrEtiqueta.length);

        var arrMascara = new Uint8Array(
            await crypto.subtle.digest('SHA-256', arrParaHash));

        var arrKeyOut = new Uint8Array(32);
        for (var i = 0; i < 32; i++) { arrKeyOut[i] = arrKey[i] ^ arrMascara[i]; }

        // 4. opaque locator of the second piece
        var arrBodyId = crypto.getRandomValues(new Uint8Array(32));
        var szBodyId  = hex(arrBodyId);

        // 4.bis EL PIN, segundo canal.
        //
        // El correo puzzle protege de quien INTERCEPTA. No protege de
        // quien entra en el buzon del destinatario: ese tiene el eHead y
        // tiene la llave. El PIN, que llega por otro camino, tapa ese
        // agujero, y tiene que entrar en la CRIPTOGRAFIA: si fuera el
        // servidor quien lo comprueba antes de dar la segunda pieza, la
        // proteccion dependeria de que nos portemos bien.
        //
        // La sal es el localizador, que ya es aleatorio y unico por
        // mensaje: dos correos con el mismo PIN no dan la misma mascara,
        // asi que no se puede precalcular una tabla y reutilizarla.
        var nIter = (szPin === PIN_DEFECTO) ? PIN_ITER_DEFECTO : PIN_ITER;

        var arrPin = await mascaraPin(szPin, arrBodyId, nIter);
        for (var p = 0; p < 32; p++) { arrKeyOut[p] ^= arrPin[p]; }

        // 5. un sobre de curva por destinatario. Cada uno lleva la llave
        //    ENMASCARADA, el localizador y el origen: los dos ultimos
        //    salen enteros, porque hay que saber que pieza pedir y a
        //    quien antes de tenerla; la llave no sirve hasta tenerlo
        //    todo.
        //
        //    Ya no son 64 bytes fijos: el origen es de largo variable y
        //    lleva delante su longitud en un byte. Cualquier sitio que
        //    siga dando por hecho el 64 lee mal el sobre.
        var arrOrigen  = new TextEncoder().encode(szOrigen);
        var arrSemilla = new Uint8Array(65 + arrOrigen.length);
        arrSemilla.set(arrKeyOut, 0);
        arrSemilla.set(arrBodyId, 32);
        arrSemilla[64] = arrOrigen.length;
        arrSemilla.set(arrOrigen, 65);

        var objEncKeys = {};
        for (var j = 0; j < arrPubs.length; j++) {
            var arrSobre = await envolver(arrSemilla, arrPubs[j]);
            objEncKeys[await huella(arrPubs[j])] = b64(arrSobre);
        }

        // 6. split. ALWAYS, and never the whole block in the header.
        var nBlock = arrCifrado.length;
        var nHead  = Math.min(MAX_HEAD, Math.floor(nBlock * RATIO_HEAD));
        nHead = Math.max(1, Math.min(nHead, nBlock - 1));

        var arrPayload = arrCifrado.slice(0, nHead);
        var arrBody    = arrCifrado.slice(nHead);

        // The order of the keys matters: the JSON has to come out the
        // same as the PHP one so that nothing depends on how each side
        // serialises it. szChecksum is NOT in: it was the value that
        // takes off the mask.
        var objHead = {
            szVersion:  VERSION,
            szAlgo:     ALGO,
            szIv:       b64(arrIv),
            szTag:      b64(arrTag),
            // Las iteraciones viajan porque subirlas manyana no puede
            // romper el correo ya repartido. Quien abre las lee de aqui.
            nPinIter:   nIter,
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
        // Se saca para que los tests puedan comprobar que dice lo mismo
        // que clsKeyFetch::dominioValido(). Dos reglas que se separen
        // producen correo que un lado sella y el otro no abre.
        dominioValido: dominioValido,
        VERSION: VERSION
    };
})();
