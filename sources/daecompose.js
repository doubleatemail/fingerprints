/**
 * DAE - Sending with the encryption done in the browser
 *
 * When it is switched on, the mail is built and sealed here, and the
 * server gets the two pieces already encrypted. Without this, the server
 * sees the message and attachments in the clear just before encrypting.
 *
 * IT IS OFF BY DEFAULT, and not out of excessive caution: today it has
 * a real drawback, and it is written on the screen instead of hidden.
 * The mail goes out UNSIGNED, because signing needs the private key of
 * the sender and it is not here: under managed custody the server keeps
 * it. Whoever receives the message will see it as not signed.
 *
 * Whoever wants both things at once, encrypting outside the server AND
 * signing, has dae_send.py, which runs on their computer and does have
 * the key. See /?page=verificar.
 */
(function () {
    'use strict';

    var objForm = document.querySelector('form.compose');
    var objCasilla = document.getElementById('bCifrarAqui');
    if (!objForm || !objCasilla || !window.daeSeal || !window.daeMimeBuild) { return; }

    var objEstado = document.getElementById('cifrarEstado');
    var ALFABETO  = 'ybndrfg8ejkmcpqxot1uwisza345h769';

    function decir(sz) {
        if (objEstado) {
            objEstado.textContent = sz;
            objEstado.hidden = (sz === '');
        }
    }

    function zbase32(arr) {
        var bits = '', i;
        for (i = 0; i < arr.length; i++) {
            bits += ('00000000' + arr[i].toString(2)).slice(-8);
        }
        var out = '';
        for (i = 0; i < bits.length; i += 5) {
            out += ALFABETO[parseInt((bits.substr(i, 5) + '0000').slice(0, 5), 2)];
        }
        return out;
    }

    /**
     * The identifier of an address in the directory.
     *
     * Only the local part, lowercased. What is asked for is not the
     * address but its digest, so that nobody can walk the directory
     * trying out names.
     */
    async function hu(szEmail) {
        var szLocal = szEmail.trim().toLowerCase().split('@')[0];
        var arr = new Uint8Array(await crypto.subtle.digest(
            'SHA-1', new TextEncoder().encode(szLocal)));
        return zbase32(arr);
    }

    function b64(arr) {
        var sz = '';
        for (var i = 0; i < arr.length; i++) { sz += String.fromCharCode(arr[i]); }
        return window.btoa(sz);
    }

    function hex(arr) {
        var sz = '';
        for (var i = 0; i < arr.length; i++) {
            sz += ('0' + arr[i].toString(16)).slice(-2);
        }
        return sz;
    }

    function deHex(sz) {
        var arr = new Uint8Array(sz.length / 2);
        for (var i = 0; i < arr.length; i++) {
            arr[i] = parseInt(sz.substr(i * 2, 2), 16);
        }
        return arr;
    }

    /**
     * Signs the message, if the user key is loaded here.
     *
     * That only happens under own custody: under managed custody the
     * server keeps the private key and here there is nothing to sign with.
     *
     * The signature goes INSIDE what is then encrypted. Outside it would
     * tell whoever intercepts the mail who wrote it, which is exactly
     * what the protocol avoids.
     *
     * The envelope has to come out the same as the one from clsSign::wrap()
     * or the recipient will see "unsigned" on a mail that is signed.
     */
    async function firmarSiSePuede(arrMime, szYo) {
        if (!window.daeCrypto || !window.daeCrypto.puedeFirmar
            || !window.daeCrypto.puedeFirmar()) {
            return arrMime;
        }

        // The fingerprint is that of the PUBLIC key, and WebCrypto does
        // not get it out of a private one. It is asked of the directory,
        // which is public by definition. That way the .daekey files
        // already exported, which do not carry it inside, need no migrating.
        //
        // Es la huella de la llave que publica el directorio, la misma
        // que indexa arrEncKeys. Identifica al firmante, no prueba nada
        // por si sola: lo que se comprueba es la firma.
        var arrPub = await clavePublicaDe(szYo);
        var szHuella = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', arrPub)));

        var arrFirma = await window.daeCrypto.firmar(arrMime);

        var szCabecera = JSON.stringify({
            szAlgo:      'Ed25519',
            szSigner:    szYo.trim().toLowerCase(),
            szSignerFp:  szHuella,
            szSignature: b64(arrFirma)
        });

        var arrSobre = new TextEncoder().encode(
            'DAE-SIG1\n' + szCabecera + '\n\n');
        var arrTodo = new Uint8Array(arrSobre.length + arrMime.length);
        arrTodo.set(arrSobre, 0);
        arrTodo.set(arrMime, arrSobre.length);
        return arrTodo;
    }

    /**
     * La llave publica X25519 de una direccion, en crudo.
     *
     * El directorio ya no sirve un PEM: son 64 caracteres hexadecimales
     * con su etiqueta delante, "curve" la de cifrar y "sign" la de
     * firmar. Aqui solo interesa la de cifrar; la de firmar la mira
     * quien verifica, que no es este lado. Ver pages/keydir.php.
     *
     * Un cuerpo que no encaje se rechaza aqui, y no mas adelante, donde
     * el fallo saldria disfrazado de "no se ha podido cifrar".
     *
     * @returns {Uint8Array} 32 bytes
     */
    async function clavePublicaDe(szEmail) {
        var objResp = await fetch('/.well-known/dae/hu/' + await hu(szEmail),
                                  { credentials: 'omit' });
        if (!objResp.ok) { throw new Error('sin_clave:' + szEmail); }

        var szHex = '';
        (await objResp.text()).split('\n').forEach(function (szLinea) {
            var arrTrozo = szLinea.trim().toLowerCase().split(/\s+/);
            if (arrTrozo[0] === 'curve') { szHex = arrTrozo[1] || ''; }
        });

        if (!/^[0-9a-f]{64}$/.test(szHex)) {
            throw new Error('clave_rara:' + szEmail);
        }
        return deHex(szHex);
    }

    function direcciones() {
        var arr = [];
        ['szTo', 'szCc'].forEach(function (szId) {
            var obj = document.getElementById(szId);
            if (!obj) { return; }
            obj.value.split(',').forEach(function (sz) {
                sz = sz.trim();
                if (sz !== '') { arr.push(sz); }
            });
        });
        return arr;
    }

    objForm.addEventListener('submit', async function (objEv) {
        if (!objCasilla.checked) { return; }   // the usual path

        var arrPara = direcciones();
        // Only @@ addresses: a normal one cannot be encrypted, and
        // mixing the two in one send is just what the server forbids.
        if (arrPara.length === 0 || arrPara.some(function (sz) { return sz.indexOf('@@') < 0; })) {
            return;   // let the server decide and warn as always
        }

        objEv.preventDefault();

        var objBoton = objForm.querySelector('button[type=submit]');
        if (objBoton) { objBoton.disabled = true; }

        try {
            decir(objCasilla.dataset.buscando || '...');
            var arrPubs = [];
            for (var i = 0; i < arrPara.length; i++) {
                arrPubs.push(await clavePublicaDe(arrPara[i]));
            }

            decir(objCasilla.dataset.montando || '...');
            var objFicheros = document.getElementById('arrFiles');
            var arrMime = await window.daeMimeBuild.montar({
                szDe:     objCasilla.dataset.yo || '',
                arrPara:  arrPara,
                szAsunto: (document.getElementById('szSubject') || {}).value || '',
                szCuerpo: (document.getElementById('szBody') || {}).value || '',
                arrFicheros: objFicheros && objFicheros.files
                    ? Array.prototype.slice.call(objFicheros.files) : []
            });

            arrMime = await firmarSiSePuede(arrMime, objCasilla.dataset.yo || '');

            // EL PIN. Sin esta linea el navegador sellaria con 000000
            // mientras el remitente cree que ha puesto uno suyo: el
            // correo saldria sin proteccion y no se enteraria nadie
            // hasta que hiciera falta. Por este camino el servidor NO ve
            // el PIN, asi que no puede tapar el hueco por nosotros.
            var objPin = document.getElementById('szPin');
            var szPin  = objPin ? objPin.value.trim() : '';

            decir(objCasilla.dataset.cifrando || '...');
            var objSello = await window.daeSeal.sellar(arrMime, arrPubs, szPin);

            decir(objCasilla.dataset.enviando || '...');
            var objDatos = new FormData();
            objDatos.append('szCsrf', (objForm.querySelector('[name=szCsrf]') || {}).value || '');
            objDatos.append('szTo', arrPara.join(', '));
            objDatos.append('szHead', objSello.szHead);
            objDatos.append('szBodyId', objSello.szBodyId);
            var objRet = document.querySelector('[name=szRetention]:checked')
                      || document.querySelector('[name=szRetention]');
            if (objRet) { objDatos.append('szRetention', objRet.value); }
            objDatos.append('ebody', new Blob([objSello.arrBody],
                            { type: 'application/octet-stream' }), 'ebody');

            var objResp = await fetch('/?page=sealed', {
                method: 'POST', body: objDatos, credentials: 'same-origin' });
            var objJson = await objResp.json();

            if (!objJson.bOk) { throw new Error(objJson.szError || 'no_enviado'); }

            // The key change warning comes back in the response. Here
            // the send cannot be stopped, it has already gone out, so
            // at least it gets told: keeping quiet would be worse.
            if (objJson.arrAvisos && objJson.arrAvisos.length) {
                alert((objCasilla.dataset.avisollave || '') + '\n\n'
                      + objJson.arrAvisos.map(function (a) { return a.szEmail; }).join('\n'));
            }

            window.location = '/?page=inbox&folder=sent&sent=1';

        } catch (e) {
            decir((objCasilla.dataset.fallo || 'Error') + ' (' + e.message + ')');
            if (objBoton) { objBoton.disabled = false; }
        }
    });
})();
