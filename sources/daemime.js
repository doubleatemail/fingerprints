/**
 * DAE - MIME reader for the browser
 *
 * Two places use it: the public demo, which puts the two pieces back
 * together in the page, and reading under own custody, where the
 * message is decrypted in the browser because the private key is not
 * on our servers.
 *
 * It understands what this system generates -- multipart with boundary
 * and parts in base64 or quoted-printable -- and nothing else. It is no
 * mail reader: for that there is the .eml and whichever program you like.
 *
 * WATCH OUT with the boundary: it is case sensitive. Lowercasing the
 * whole Content-Type header to compare the type takes the boundary down
 * with it and the message comes out empty with no error at all. It hit
 * the PHP reader on 2026-08-09 and it is written down in testMime.php.
 */

window.daeMime = (function () {
    'use strict';

    function cabecera(szHeaders, szName) {
        var re = new RegExp('^' + szName + ':\\s*([^\\r\\n]*(?:\\r?\\n[ \\t][^\\r\\n]*)*)', 'im');
        var m = szHeaders.match(re);
        return m ? m[1].replace(/\r?\n[ \t]+/g, ' ').trim() : '';
    }

    function parametro(szHeader, szParam) {
        var m = szHeader.match(new RegExp(';\\s*' + szParam + '\\s*=\\s*"([^"]*)"', 'i'))
             || szHeader.match(new RegExp(';\\s*' + szParam + '\\s*=\\s*([^;\\s]+)', 'i'));
        return m ? m[1] : '';
    }

    function partir(szParte) {
        var n = szParte.indexOf('\r\n\r\n');
        var l = 4;
        if (n === -1) { n = szParte.indexOf('\n\n'); l = 2; }
        if (n === -1) { return [szParte, '']; }
        return [szParte.slice(0, n), szParte.slice(n + l)];
    }

    function deB64(szB64) {
        var szBin = atob(szB64.replace(/\s+/g, ''));
        var arr = new Uint8Array(szBin.length);
        for (var i = 0; i < szBin.length; i++) { arr[i] = szBin.charCodeAt(i); }
        return arr;
    }

    function deQp(sz) {
        return sz.replace(/=\r?\n/g, '')
                 .replace(/=([0-9A-Fa-f]{2})/g, function (_, h) {
                     return String.fromCharCode(parseInt(h, 16));
                 });
    }

    /** Bytes -> UTF-8 text, without breaking on the accents */
    function texto(arrBytes) {
        try {
            return new TextDecoder('utf-8').decode(arrBytes);
        } catch (e) {
            var s = '';
            for (var i = 0; i < arrBytes.length; i++) { s += String.fromCharCode(arrBytes[i]); }
            return s;
        }
    }

    function bytesDeTexto(sz) {
        var arr = new Uint8Array(sz.length);
        for (var i = 0; i < sz.length; i++) { arr[i] = sz.charCodeAt(i) & 0xff; }
        return arr;
    }

    /**
     * Pulls out of a message its subject, sender, text and files.
     *
     * @param {string} szRaw the raw MIME, already decrypted
     */
    function leer(szRaw) {
        var arrTop  = partir(szRaw);
        var szTipo  = cabecera(arrTop[0], 'Content-Type');
        var objOut  = {
            szSubject: descodificarCabecera(cabecera(arrTop[0], 'Subject')),
            szFrom:    descodificarCabecera(cabecera(arrTop[0], 'From')),
            szTo:      descodificarCabecera(cabecera(arrTop[0], 'To')),
            szText:    '',
            szHtml:    '',
            arrFiles:  []
        };

        recorrer(arrTop[0], arrTop[1], objOut);
        return objOut;
    }

    function recorrer(szHeaders, szBody, objOut) {
        var szTipo = cabecera(szHeaders, 'Content-Type');
        var szTipoBajo = szTipo.toLowerCase();

        if (szTipoBajo.indexOf('multipart/') === 0) {
            // the boundary is read from the ORIGINAL, with its capitals
            var szFrontera = parametro(szTipo, 'boundary');
            if (!szFrontera) { return; }

            var arrPartes = szBody.split('--' + szFrontera);
            for (var i = 0; i < arrPartes.length; i++) {
                var szTrozo = arrPartes[i].replace(/^\r?\n/, '');
                if (!szTrozo || szTrozo.indexOf('--') === 0) { continue; }
                var arrP = partir(szTrozo);
                recorrer(arrP[0], arrP[1], objOut);
            }
            return;
        }

        var szEnc  = cabecera(szHeaders, 'Content-Transfer-Encoding').toLowerCase();
        var szDisp = cabecera(szHeaders, 'Content-Disposition');
        var szName = parametro(szDisp, 'filename') || parametro(szTipo, 'name');

        var arrBytes;
        if (szEnc === 'base64')            { arrBytes = deB64(szBody); }
        else if (szEnc === 'quoted-printable') { arrBytes = bytesDeTexto(deQp(szBody)); }
        else                               { arrBytes = bytesDeTexto(szBody); }

        if (szName || szDisp.toLowerCase().indexOf('attachment') === 0) {
            objOut.arrFiles.push({
                szName: descodificarCabecera(szName) || 'adjunto',
                szMime: szTipo.split(';')[0].trim().toLowerCase() || 'application/octet-stream',
                arrBytes: arrBytes
            });
            return;
        }

        if (szTipoBajo.indexOf('text/html') === 0) {
            if (!objOut.szHtml) { objOut.szHtml = texto(arrBytes); }
        } else if (!objOut.szText) {
            objOut.szText = texto(arrBytes);
        }
    }

    /** Headers with =?UTF-8?B?...?= */
    function descodificarCabecera(sz) {
        if (!sz || sz.indexOf('=?') === -1) { return (sz || '').trim(); }
        return sz.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, function (_, cs, tipo, dato) {
            try {
                var arr = tipo.toUpperCase() === 'B'
                    ? deB64(dato)
                    : bytesDeTexto(deQp(dato.replace(/_/g, ' ')));
                return texto(arr);
            } catch (e) { return dato; }
        }).trim();
    }

    return { leer: leer, deB64: deB64, texto: texto };
})();
