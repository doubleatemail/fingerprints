/**
 * DAE - Lector de MIME para el navegador
 *
 * Lo usan dos sitios: la demostracion publica, que junta las dos piezas
 * en la pagina, y la lectura en custodia propia, donde el mensaje se
 * descifra en el navegador porque la clave privada no esta en nuestros
 * servidores.
 *
 * Entiende lo que este sistema genera —multiparte con frontera y partes
 * en base64 o quoted-printable— y nada mas. No pretende ser un lector de
 * correo: para eso esta el .eml y el programa que cada uno prefiera.
 *
 * OJO con la frontera: es sensible a mayusculas. Pasar la cabecera
 * Content-Type entera a minusculas para comparar el tipo se lleva por
 * delante la frontera y el mensaje sale vacio sin dar ningun error. Le
 * paso al lector de PHP el 2026-08-09 y esta escrito en testMime.php.
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

    /** Bytes -> texto UTF-8, sin romperse con los acentos */
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
     * Saca de un mensaje su asunto, su remitente, su texto y sus ficheros.
     *
     * @param {string} szRaw el MIME crudo, ya descifrado
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
            // la frontera se lee del ORIGINAL, con sus mayusculas
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

    /** Cabeceras con =?UTF-8?B?...?= */
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
