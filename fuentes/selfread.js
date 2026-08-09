/**
 * DAE - Pantalla de lectura en custodia propia
 *
 * Engancha el formulario de la clave con daecrypto.js y pinta el mensaje
 * ya descifrado. Todo el trabajo pasa en esta pestanya: el servidor
 * mando el eHead —que sin la clave no dice nada— y nada mas.
 *
 * La clave se queda en memoria mientras la pestanya viva. Al recargar
 * hay que volver a ponerla, y es a proposito: guardarla en el navegador
 * seria comodo hoy y un disgusto el dia que alguien use ese ordenador.
 */

(function () {
    'use strict';

    var elCaja = document.getElementById('daeSelf');
    if (!elCaja) { return; }

    var szHead  = (document.getElementById('daeSelfHead') || {}).textContent || '';
    var elForm  = document.getElementById('daeSelfForm');
    var elFile  = document.getElementById('daeSelfFile');
    var elPass  = document.getElementById('daeSelfPass');
    var elAviso = document.getElementById('daeSelfAviso');
    var elSalida = document.getElementById('daeSelfSalida');
    var arrUrls = [];

    function aviso(szTexto) {
        elAviso.textContent = szTexto;
        elAviso.removeAttribute('hidden');
    }

    function motivo(szCodigo) {
        var arr = {
            frase:         elCaja.dataset.errFrase,
            formato:       elCaja.dataset.errFormato,
            no_es_para_ti: elCaja.dataset.errAjeno,
            alterado:      elCaja.dataset.errAlterado,
            pieza_no_esta: elCaja.dataset.errSinPieza,
            pieza_error:   elCaja.dataset.errSinPieza,
            sin_clave:     elCaja.dataset.errSinClave,
            cabecera:      elCaja.dataset.errFormato
        };
        return arr[szCodigo] || elCaja.dataset.errGenerico;
    }

    function leerFichero(objFile) {
        return new Promise(function (resolver, rechazar) {
            var objLector = new FileReader();
            objLector.onload = function () { resolver(String(objLector.result)); };
            objLector.onerror = function () { rechazar(new Error('formato')); };
            objLector.readAsText(objFile);
        });
    }

    function escapar(sz) {
        var el = document.createElement('div');
        el.textContent = sz;
        return el.innerHTML;
    }

    function pintar(objMsg) {
        elForm.setAttribute('hidden', '');
        elAviso.setAttribute('hidden', '');

        var szHtml = '<dl class="kv">'
            + '<dt>' + escapar(elCaja.dataset.lblDe) + '</dt><dd>' + escapar(objMsg.szFrom) + '</dd>'
            + '<dt>' + escapar(elCaja.dataset.lblAsunto) + '</dt><dd>' + escapar(objMsg.szSubject) + '</dd>'
            + '</dl>'
            + '<pre class="msg-body-text">' + escapar(objMsg.szText) + '</pre>';

        if (objMsg.arrFiles.length) {
            szHtml += '<div class="recovered"><h3>' + escapar(elCaja.dataset.lblFicheros) + '</h3>';
            for (var i = 0; i < objMsg.arrFiles.length; i++) {
                var f = objMsg.arrFiles[i];
                var szUrl = URL.createObjectURL(new Blob([f.arrBytes], { type: f.szMime }));
                arrUrls.push(szUrl);
                szHtml += '<div class="recovered-file">';
                if (f.szMime.indexOf('image/') === 0) {
                    szHtml += '<img src="' + szUrl + '" alt="' + escapar(f.szName) + '">';
                } else if (f.szMime.indexOf('video/') === 0) {
                    szHtml += '<video controls playsinline preload="metadata" src="' + szUrl + '"></video>';
                }
                szHtml += '<a href="' + szUrl + '" download="' + escapar(f.szName) + '">'
                       + escapar(f.szName) + ' (' + Math.round(f.arrBytes.length / 1024) + ' KB)</a></div>';
            }
            szHtml += '</div>';
        }

        elSalida.innerHTML = szHtml;
        elSalida.removeAttribute('hidden');
    }

    elForm.addEventListener('submit', async function (objEv) {
        objEv.preventDefault();
        elAviso.setAttribute('hidden', '');

        if (!elFile.files || !elFile.files.length) {
            aviso(elCaja.dataset.errSinFichero);
            return;
        }

        try {
            if (!window.daeCrypto.lista()) {
                var szJson = await leerFichero(elFile.files[0]);
                await window.daeCrypto.cargar(szJson, elPass.value);
            }
            var szCrudo = await window.daeCrypto.abrir(szHead, '');
            pintar(window.daeMime.leer(szCrudo));
        } catch (objErr) {
            window.daeCrypto.olvidar();          // que no quede a medias
            aviso(motivo(objErr.message));
        }
    });

    window.addEventListener('pagehide', function () {
        window.daeCrypto.olvidar();
        for (var i = 0; i < arrUrls.length; i++) { URL.revokeObjectURL(arrUrls[i]); }
    });
})();
