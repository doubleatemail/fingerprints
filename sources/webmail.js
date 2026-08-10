/**
 * DAE Webmail - client side
 *
 * Live protocol indicator while composing. The address decides how the
 * message travels, so the user must SEE which one is going to be used
 * before pressing send, not find out afterwards.
 */
(function () {
    'use strict';

    var szTo    = document.getElementById('szTo');
    var szCc    = document.getElementById('szCc');
    var objBox  = document.getElementById('protocolBox');
    var objBadge= document.getElementById('protoBadge');
    var objText = document.getElementById('protoText');

    if (!objBox || !szTo) { return; }

    // Texts come from data attributes so nothing is hardcoded here
    var arrTexts = {
        plain: objBox.dataset.plain || '',
        atat:  objBox.dataset.atat  || '',
        mixed: objBox.dataset.mixed || ''
    };

    function detect() {
        var szAll = (szTo.value || '') + ',' + (szCc ? (szCc.value || '') : '');
        var arrParts = szAll.split(/[,;]+/).map(function (s) { return s.trim(); })
                            .filter(function (s) { return s !== ''; });

        var bHasAtAt  = false;
        var bHasPlain = false;

        arrParts.forEach(function (szOne) {
            if (szOne.indexOf('@@') !== -1) { bHasAtAt = true; }
            else if (szOne.indexOf('@') !== -1) { bHasPlain = true; }
        });

        objBox.classList.remove('proto-is-atat', 'proto-is-plain', 'proto-is-mixed');

        if (bHasAtAt && bHasPlain) {
            objBox.classList.add('proto-is-mixed');
            objBadge.textContent = '@ @@';
            objText.textContent  = arrTexts.mixed;
        } else if (bHasAtAt) {
            objBox.classList.add('proto-is-atat');
            objBadge.textContent = '@@';
            objText.textContent  = arrTexts.atat;
        } else {
            objBox.classList.add('proto-is-plain');
            objBadge.textContent = '@';
            objText.textContent  = arrTexts.plain;
        }
    }

    szTo.addEventListener('input', detect);
    if (szCc) { szCc.addEventListener('input', detect); }
    detect();

    // Contador de ficheros elegidos. El texto viene del servidor, para
    // que siga siendo multiidioma.
    var objFiles = document.getElementById('arrFiles');
    var objList  = document.getElementById('fileList');
    if (objFiles && objList) {
        var szNone = objList.textContent;
        var szMany = objList.dataset.many || '{0}';
        objFiles.addEventListener('change', function () {
            var n = objFiles.files ? objFiles.files.length : 0;
            if (n === 0)      { objList.textContent = szNone; objList.classList.remove('has-files'); }
            else if (n === 1) { objList.textContent = objFiles.files[0].name; objList.classList.add('has-files'); }
            else              { objList.textContent = szMany.replace('{0}', n); objList.classList.add('has-files'); }
        });
    }
})();


/**
 * Aviso de cookies.
 *
 * Bloque aparte a proposito: el de arriba se corta pronto si no hay caja
 * de redaccion, asi que aqui dentro no se ejecutaria nunca en la web
 * publica, que es justo donde hace falta.
 *
 * El "ya lo he leido" se guarda en localStorage y no en una cookie. Seria
 * un chiste malo poner una cookie para recordar que te hemos dicho que no
 * usamos cookies. Ademas localStorage no viaja al servidor: ese dato no
 * sale del navegador de quien lee.
 */
(function () {
    'use strict';

    var objBar = document.getElementById('cookieBar');
    var objOk  = document.getElementById('cookieOk');
    if (!objBar || !objOk) { return; }

    var szClave = 'dae.aviso.cookies';

    // En navegacion privada algunos navegadores tienen localStorage pero
    // lanzan al escribir. Si no se puede guardar, la barra sale siempre:
    // molesta, pero es lo honesto. Fingir que se recordo seria peor.
    function leido() {
        try { return window.localStorage.getItem(szClave) === '1'; }
        catch (e) { return false; }
    }
    function anotar() {
        try { window.localStorage.setItem(szClave, '1'); }
        catch (e) { /* sin sitio donde anotarlo: volvera a salir */ }
    }

    if (leido()) { return; }

    // La clase sube el boton flotante mientras el aviso ocupa el borde
    // inferior. Sin esto se solapan y uno de los dos queda inservible.
    objBar.hidden = false;
    document.body.classList.add('con-aviso');

    objOk.addEventListener('click', function () {
        anotar();
        objBar.hidden = true;
        document.body.classList.remove('con-aviso');
    });
})();
