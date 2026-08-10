/**
 * DAE - Reading puzzle mail in self custody
 *
 * This is where self custody stops being a promise: the private key is
 * NOT on our servers, so the message is decrypted in the browser of
 * whoever receives it. We cannot read it, and this is what makes it
 * true and not a marketing line.
 *
 * What it does, in order:
 *
 *   1. Opens the .daekey file with the password the user puts in. It is
 *      our own simple format --PBKDF2 + AES-256-GCM over a PKCS#8--
 *      because WebCrypto cannot open a protected PKCS#8: it does not
 *      implement PBES2. That is why the usual .pem is no good as is.
 *   2. With that key it opens one arrEncKeys entry of the eHead and
 *      takes out two things: the AES key of the message and the locator
 *      of the other piece.
 *   3. Asks for that piece at /ebody/<locator>. The server does not get
 *      who is asking nor which message it is about: it cannot know.
 *   4. Puts the two together, decrypts with AES-256-GCM, checks the tag.
 *
 * The decrypted key lives in memory and only while the tab lasts. It is
 * not saved in localStorage nor in a cookie on purpose: what is not
 * written down nobody takes away.
 */

window.daeCrypto = (function () {
    'use strict';

    var objFirma = null;   // the same key, for signing

    var objClave = null;      // CryptoKey in memory, nothing else
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

    /** Is there a key loaded in this tab? */
    function lista() { return objClave !== null; }

    function duenyo() { return szQuien; }

    /**
     * Opens the .daekey and leaves the key ready for this tab.
     *
     * @param {string} szJson  contents of the file
     * @param {string} szFrase password the user put in when exporting
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

        // PBKDF2 over the password, with the parameters that come inside
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
            // The GCM tag does not add up: that is not the password
            throw new Error('frase');
        }

        // SHA-1 is not an oversight: it is what OpenSSL uses by default
        // in RSA-OAEP, and it is what the messages were sealed with.
        // Changing it here would make all the mail already received
        // unreadable.
        objClave = await crypto.subtle.importKey(
            'pkcs8', arrPkcs8,
            { name: 'RSA-OAEP', hash: 'SHA-1' },
            false, ['decrypt']);

        // The SAME key, imported again for signing. WebCrypto does not
        // let a decryption key be used for signing, and it is right to:
        // separating what each key is for prevents attacks where you
        // make somebody sign something they thought they were decrypting.
        //
        // PKCS#1 v1.5 with SHA-256, which is what openssl_sign does on
        // the server. If it did not match, the recipient would see
        // "invalid signature" on a perfectly legitimate mail, which is
        // scarier than not signing it.
        try {
            objFirma = await crypto.subtle.importKey(
                'pkcs8', arrPkcs8,
                { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
                false, ['sign']);
        } catch (e) {
            // Not being able to sign does not stop you reading, which
            // is what you came for. Carry on without signature, done.
            objFirma = null;
        }

        szQuien = objSobre.szEmail || '';
        return szQuien;
    }

    /** Forgets the key. Called on the way out. */
    function olvidar() { objClave = null; objFirma = null; szQuien = ''; }

    /** True if the loaded key can also sign. */
    function puedeFirmar() { return objFirma !== null; }

    /**
     * Signs some bytes with the loaded key.
     *
     * Returns the raw signature. The caller assembles the envelope,
     * because the envelope format is the protocol's business and not
     * the cryptography's.
     */
    async function firmar(arrDatos) {
        if (!objFirma) { throw new Error('sin_clave_de_firma'); }
        return new Uint8Array(await crypto.subtle.sign(
            { name: 'RSASSA-PKCS1-v1_5' }, objFirma, arrDatos));
    }

    /**
     * Puts the two pieces together and returns the MIME in the clear.
     *
     * @param {string} szHead  the eHead, just as it arrived (JSON)
     * @param {string} szBase  where to download the second piece from
     */
    async function abrir(szHead, szBase) {
        if (!objClave) { throw new Error('sin_clave'); }

        var objHead;
        try {
            objHead = JSON.parse(szHead);
        } catch (e) {
            throw new Error('cabecera');
        }

        // Every entry gets tried: a message can go sealed for several
        // recipients and only one of them is ours. The rest failing is
        // the normal thing.
        var arrAbierta = null;
        var arrEnc = objHead.arrEncKeys || {};
        for (var szHuella in arrEnc) {
            if (!Object.prototype.hasOwnProperty.call(arrEnc, szHuella)) { continue; }
            try {
                var arrCrudo = new Uint8Array(await crypto.subtle.decrypt(
                    { name: 'RSA-OAEP' }, objClave, deB64(arrEnc[szHuella])));
                if (arrCrudo.length === 64) { arrAbierta = arrCrudo; break; }
            } catch (e) { /* it was not ours */ }
        }

        if (!arrAbierta) { throw new Error('no_es_para_ti'); }

        var arrClaveAes = arrAbierta.slice(0, 32);
        var szLocaliza  = hex(arrAbierta.slice(32));

        // The second piece. The locator IS the credential.
        var objResp = await fetch(szBase + '/ebody/' + szLocaliza, { credentials: 'omit' });
        if (!objResp.ok) {
            throw new Error(objResp.status === 404 ? 'pieza_no_esta' : 'pieza_error');
        }
        var arrBody = new Uint8Array(await objResp.arrayBuffer());

        // The full ciphertext: the two pieces, without the tag yet.
        var arrPayload = deB64(objHead.szPayload);
        var arrTag     = deB64(objHead.szTag);
        var arrCifrado = new Uint8Array(arrPayload.length + arrBody.length);
        arrCifrado.set(arrPayload, 0);
        arrCifrado.set(arrBody, arrPayload.length);

        // ALL-OR-NOTHING TRANSFORM (DAE-2). The key that came in the
        // header is not the key: it comes masked with the digest of the
        // WHOLE ciphertext. Here the mask is taken off, and it can only
        // be done because both pieces are already here. If one byte
        // were missing another key would come out and the decrypt below
        // would fail, without letting one chunk of the message be read.
        //
        // DAE-1 did not carry it and its key goes as is: there is old
        // mail delivered in that format and it still opens.
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

        // And now the tag stuck at the end, the way WebCrypto expects.
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
            // The tag does not add up: pieces altered or incomplete
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
