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

    // Counter of chosen files. The text comes from the server, so it
    // stays multilingual.
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
 * Cookie notice.
 *
 * A separate block on purpose: the one above bails out early if there is
 * no compose box, so this code would never run on the public site,
 * which is exactly where it is needed.
 *
 * The "I already read it" flag goes to localStorage and not to a cookie.
 * It would be a bad joke to set a cookie just to remember that we told
 * you we do not use cookies. Besides, localStorage never travels to the
 * server: that bit never leaves the reader's browser.
 */
(function () {
    'use strict';

    var objBar = document.getElementById('cookieBar');
    var objOk  = document.getElementById('cookieOk');
    if (!objBar || !objOk) { return; }

    var szClave = 'dae.aviso.cookies';

    // In private browsing some browsers do have localStorage but throw
    // on write. If it cannot be saved, the bar shows up every time:
    // annoying, but honest. Pretending we remembered would be worse.
    function leido() {
        try { return window.localStorage.getItem(szClave) === '1'; }
        catch (e) { return false; }
    }
    function anotar() {
        try { window.localStorage.setItem(szClave, '1'); }
        catch (e) { /* nowhere to write it down: it will show again */ }
    }

    if (leido()) { return; }

    // The class lifts the floating button while the notice takes the
    // bottom edge. Without this they overlap and one of the two is
    // unusable.
    objBar.hidden = false;
    document.body.classList.add('con-aviso');

    objOk.addEventListener('click', function () {
        anotar();
        objBar.hidden = true;
        document.body.classList.remove('con-aviso');
    });
})();
