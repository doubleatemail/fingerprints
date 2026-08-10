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
 * Un solo formato, DAE-3, y a proposito. RSA se borro entero el
 * 2026-08-10, con el sistema sin usuarios reales: sostener dos caminos
 * de cifrado que no usaba nadie era pagar para siempre por nada. Ver
 * clsEBlock.php y 06_AT_AT_PROTOCOL.md, seccion 3.ter.
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
    var VERSION       = 'DAE-3';
    var ALGO          = 'A256GCM+X25519+AONT';
    var MAX_HEAD      = 102400;   // 100 KB
    var RATIO_HEAD    = 0.10;     // 10 %

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
     * Seals a message for one or several public keys.
     *
     * Las publicas llegan en crudo, 32 bytes cada una. No hay PEM que
     * parsear: el directorio publica hexadecimal y quien llama ya lo ha
     * pasado a bytes.
     *
     * @param {Uint8Array}   arrPlain  the inner MIME, already assembled
     * @param {Uint8Array[]} arrPubs   X25519 keys of the recipients
     * @returns {{szHead:string, arrBody:Uint8Array, szBodyId:string}}
     */
    async function sellar(arrPlain, arrPubs) {
        if (!arrPlain || arrPlain.length === 0) { throw new Error('mensaje_vacio'); }
        if (!arrPubs || arrPubs.length === 0)   { throw new Error('sin_claves'); }

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

        // 5. un sobre de curva por destinatario. Cada uno lleva la llave
        //    ENMASCARADA y el localizador: el localizador sale entero,
        //    porque hay que saber que pieza pedir antes de tenerla; la
        //    llave no sirve hasta tenerlo todo.
        var arrSemilla = new Uint8Array(64);
        arrSemilla.set(arrKeyOut, 0);
        arrSemilla.set(arrBodyId, 32);

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
