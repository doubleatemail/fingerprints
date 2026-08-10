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
 * A LIMIT THAT IS HIDDEN FROM NOBODY: this file is served by our
 * server. A compromised server could send a version that snitches. This
 * reduces the daily exposure, it does NOT remove the trust. Whoever
 * does not want to trust has dae_send.py and dae_open.py, which can be
 * read end to end and work without us. See /?page=verificar.
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

    /** The body of a PEM, no headers and no breaks: the DER bytes. */
    function der(szPem) {
        return deB64(szPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
    }

    /**
     * The fingerprint has to come out the same as in
     * clsKeys::fingerprint(): SHA-256 in hex over the DER bytes of the
     * public key. It is the one that indexes arrEncKeys, so if it does
     * not match the recipient does not find their entry.
     */
    async function huella(szPem) {
        return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', der(szPem))));
    }

    /**
     * RSA-OAEP with SHA-1, which is what OpenSSL uses by default and
     * therefore what is in all the mail already delivered. Changing it
     * here would leave the messages unreadable for the rest of the
     * system.
     */
    async function importarPublica(szPem) {
        return crypto.subtle.importKey(
            'spki', der(szPem),
            { name: 'RSA-OAEP', hash: 'SHA-1' },
            false, ['encrypt']);
    }

    /**
     * Seals a message for one or several public keys.
     *
     * @param {Uint8Array} arrPlain  the inner MIME, already assembled
     * @param {string[]}   arrPems   public keys of the recipients
     * @returns {{szHead:string, arrBody:Uint8Array, szBodyId:string}}
     */
    async function sellar(arrPlain, arrPems) {
        if (!arrPlain || arrPlain.length === 0) { throw new Error('mensaje_vacio'); }
        if (!arrPems || arrPems.length === 0)   { throw new Error('sin_claves'); }

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

        // 5. one RSA operation per recipient. Each one carries the
        //    MASKED key and the locator: the locator goes out whole,
        //    because you must know which piece to ask for before having
        //    it.
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
