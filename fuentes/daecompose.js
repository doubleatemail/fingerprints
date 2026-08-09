/**
 * DAE - Enviar cifrando en el navegador
 *
 * Cuando esta activado, el correo se monta y se cierra aqui, y al
 * servidor le llegan las dos piezas ya cifradas. Sin esto, el servidor
 * ve el mensaje y los adjuntos en claro justo antes de cifrarlos.
 *
 * VA APAGADO POR DEFECTO, y no por prudencia excesiva: hoy tiene una
 * pega de verdad, y esta escrita en la pantalla en lugar de escondida.
 * El correo sale SIN FIRMAR, porque firmar necesita la clave privada del
 * remitente y aqui no esta: en custodia gestionada la guarda el servidor.
 * Quien reciba el mensaje lo vera como no firmado.
 *
 * Quien quiera las dos cosas a la vez, cifrar fuera del servidor Y
 * firmar, tiene dae_send.py, que corre en su ordenador y si tiene la
 * clave. Ver /?page=verificar.
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
     * El identificador de una direccion en el directorio.
     *
     * Solo la parte local, en minusculas. No se pregunta por la
     * direccion sino por su resumen, para que nadie pueda recorrer el
     * directorio probando nombres.
     */
    async function hu(szEmail) {
        var szLocal = szEmail.trim().toLowerCase().split('@')[0];
        var arr = new Uint8Array(await crypto.subtle.digest(
            'SHA-1', new TextEncoder().encode(szLocal)));
        return zbase32(arr);
    }

    async function clavePublicaDe(szEmail) {
        var objResp = await fetch('/.well-known/dae/hu/' + await hu(szEmail),
                                  { credentials: 'omit' });
        if (!objResp.ok) { throw new Error('sin_clave:' + szEmail); }
        return objResp.text();
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
        if (!objCasilla.checked) { return; }   // camino de siempre

        var arrPara = direcciones();
        // Solo direcciones @@: una normal no se puede cifrar, y mezclar
        // las dos cosas en un envio es justo lo que el servidor prohibe.
        if (arrPara.length === 0 || arrPara.some(function (sz) { return sz.indexOf('@@') < 0; })) {
            return;   // que decida el servidor y avise como siempre
        }

        objEv.preventDefault();

        var objBoton = objForm.querySelector('button[type=submit]');
        if (objBoton) { objBoton.disabled = true; }

        try {
            decir(objCasilla.dataset.buscando || '...');
            var arrPems = [];
            for (var i = 0; i < arrPara.length; i++) {
                arrPems.push(await clavePublicaDe(arrPara[i]));
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

            decir(objCasilla.dataset.cifrando || '...');
            var objSello = await window.daeSeal.sellar(arrMime, arrPems);

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

            // El aviso de cambio de llave llega en la respuesta. Aqui no
            // se puede parar el envio, que ya ha salido, asi que al menos
            // se cuenta: callarlo seria peor.
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
