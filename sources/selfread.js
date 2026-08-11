/**
 * DAE - Self-custody reading screen
 *
 * Wires the key form to daecrypto.js and paints the message once it is
 * decrypted. All the work happens in this tab: the server sent the
 * eHead -- which says nothing without the key -- and nothing else.
 *
 * The key stays in memory only while the tab lives. On reload you have
 * to type it again, and that is on purpose: keeping it in the browser
 * would be handy today and a disaster the day someone else uses that
 * computer.
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
    var elPin   = document.getElementById('daeSelfPin');
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
            cabecera:      elCaja.dataset.errFormato,
            // El origen sellado no es un dominio al que se pueda
            // preguntar. Es cabecera mal formada desde el punto de vista
            // de quien lee, y ademas es el sintoma de que alguien ha
            // intentado usar este mensaje para hacernos llamar a un
            // sitio suyo. Se cuenta como formato, no como "falta la
            // pieza": la pieza no falta, es que no se va a ir a buscar.
            origen_malo:   elCaja.dataset.errFormato
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
        // textContent -> innerHTML escapa &, < y >, pero NO la comilla.
        // Aqui el resultado se mete dentro de atributos entrecomillados
        // (alt="...", download="..."), y el dato es el nombre de un
        // adjunto, que lo escribe quien envia el correo: una comilla
        // cierra el atributo y deja meter onload= en la etiqueta que el
        // propio codigo ya emite. Sin un solo clic, y en la pantalla
        // donde esta cargada la llave privada.
        //
        // Se escapan las dos comillas a mano. demo.js resuelve lo mismo
        // construyendo los nodos con createElement y textContent, que es
        // mejor porque no hay nada que recordar escapar; esto es el
        // arreglo minimo mientras esta pantalla siga armando HTML.
        return String(sz)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
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
            // El PIN, si el correo lleva. Va vacio casi siempre y
            // entonces daecrypto usa el de por defecto. Sin esto, un
            // correo con PIN no se podria abrir NUNCA con la llave
            // propia: se quedaria en "alterado" sin decir por que.
            var szPin = elPin ? elPin.value.trim() : '';
            var szCrudo = await window.daeCrypto.abrir(szHead, '', szPin);
            pintar(window.daeMime.leer(szCrudo));
        } catch (objErr) {
            window.daeCrypto.olvidar();          // leave nothing half-done
            aviso(motivo(objErr.message));
        }
    });

    window.addEventListener('pagehide', function () {
        window.daeCrypto.olvidar();
        for (var i = 0; i < arrUrls.length; i++) { URL.revokeObjectURL(arrUrls[i]); }
    });
})();
