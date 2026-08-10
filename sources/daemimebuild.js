/**
 * DAE - Building the MIME of a mail IN THE BROWSER
 *
 * daemime.js knows how to READ a mail already decrypted. This is the
 * opposite: it builds the message, with its attachments, so that
 * daeseal.js encrypts it before it leaves here.
 *
 * Without this, encrypting in the browser is worth nothing: you would
 * have to send the text and the files to the server so it builds the
 * message, and by then it has seen them, which is just what we avoid.
 *
 * On the server clsAtAt::buildInnerMime() builds it with PHPMailer.
 * What comes out of here need not match that byte for byte: what has
 * to come out is correct MIME, that any mail program opens and that
 * clsMime understands on screen. There is a test for that.
 *
 * Written by hand, no library: it is four rules, and adding a
 * dependency would mean the user has to review that library too
 * before trusting it. The verify page publishes the fingerprint of
 * this file, and the shorter it is, the better it reads.
 */
window.daeMimeBuild = (function () {
    'use strict';

    /**
     * Header with text that may carry accents.
     *
     * A subject with enyes cannot travel as it is: mail is from 1982
     * and headers are ASCII. It gets encoded RFC 2047 style. If it is
     * pure ASCII it is left alone, which reads better for whoever
     * looks at the raw message.
     */
    function cabecera(nombre, valor) {
        valor = String(valor === undefined || valor === null ? '' : valor);

        // No line breaks in a header: that is the way fake headers
        // slip in (injection), like a Bcc that the sender never
        // wrote.
        valor = valor.replace(/[\r\n]+/g, ' ').trim();

        if (/^[\x20-\x7E]*$/.test(valor)) {
            return nombre + ': ' + valor + '\r\n';
        }

        var arrBytes = new TextEncoder().encode(valor);
        return nombre + ': =?UTF-8?B?' + b64(arrBytes) + '?=\r\n';
    }

    function b64(arr) {
        var s = '';
        for (var i = 0; i < arr.length; i++) { s += String.fromCharCode(arr[i]); }
        return window.btoa(s);
    }

    /** base64 in lines of 76, as the format demands. */
    function b64Lineas(arr) {
        var sz = b64(arr);
        var out = '';
        for (var i = 0; i < sz.length; i += 76) {
            out += sz.slice(i, i + 76) + '\r\n';
        }
        return out;
    }

    function frontera() {
        var arr = crypto.getRandomValues(new Uint8Array(16));
        var s = '';
        for (var i = 0; i < arr.length; i++) {
            s += ('0' + arr[i].toString(16)).slice(-2);
        }
        return '----=_DAE_' + s;
    }

    /**
     * The date, in mail format and always in UTC.
     *
     * On purpose: the timezone of whoever writes says where they are,
     * and this message goes encrypted precisely so as not to tell more.
     */
    function fecha() {
        var arrDia = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        var arrMes = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                      'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        var d = new Date();
        function dd(n) { return (n < 10 ? '0' : '') + n; }
        return arrDia[d.getUTCDay()] + ', ' + dd(d.getUTCDate()) + ' '
             + arrMes[d.getUTCMonth()] + ' ' + d.getUTCFullYear() + ' '
             + dd(d.getUTCHours()) + ':' + dd(d.getUTCMinutes()) + ':'
             + dd(d.getUTCSeconds()) + ' +0000';
    }

    function leer(objFile) {
        return new Promise(function (resolver, rechazar) {
            var objLector = new FileReader();
            objLector.onload  = function () { resolver(new Uint8Array(objLector.result)); };
            objLector.onerror = function () { rechazar(new Error('fichero_ilegible')); };
            objLector.readAsArrayBuffer(objFile);
        });
    }

    function unir(arrTrozos) {
        var n = 0, i;
        for (i = 0; i < arrTrozos.length; i++) { n += arrTrozos[i].length; }
        var out = new Uint8Array(n), pos = 0;
        for (i = 0; i < arrTrozos.length; i++) {
            out.set(arrTrozos[i], pos);
            pos += arrTrozos[i].length;
        }
        return out;
    }

    function texto(sz) { return new TextEncoder().encode(sz); }

    /**
     * Builds the whole message.
     *
     * @param {object} obj  {szDe, arrPara, szAsunto, szCuerpo, arrFicheros}
     *                      arrFicheros are File objects from the form
     * @returns {Uint8Array} the MIME ready to encrypt
     */
    async function montar(obj) {
        var arrPara = obj.arrPara || [];
        var arrFich = obj.arrFicheros || [];

        var szCab = '';
        szCab += cabecera('Date', fecha());
        szCab += cabecera('From', obj.szDe || '');
        szCab += cabecera('To', arrPara.join(', '));
        szCab += cabecera('Subject', obj.szAsunto || '');
        szCab += 'MIME-Version: 1.0\r\n';

        var arrCuerpo = texto(String(obj.szCuerpo === undefined ? '' : obj.szCuerpo));

        // With no attachments there is no need for a multipart: a
        // single part message reads the same and takes up less.
        if (arrFich.length === 0) {
            szCab += 'Content-Type: text/plain; charset=UTF-8\r\n';
            szCab += 'Content-Transfer-Encoding: base64\r\n\r\n';
            return unir([texto(szCab), texto(b64Lineas(arrCuerpo))]);
        }

        var szFront = frontera();
        szCab += 'Content-Type: multipart/mixed; boundary="' + szFront + '"\r\n\r\n';

        var arrPartes = [texto(szCab)];

        arrPartes.push(texto(
            '--' + szFront + '\r\n'
            + 'Content-Type: text/plain; charset=UTF-8\r\n'
            + 'Content-Transfer-Encoding: base64\r\n\r\n'
            + b64Lineas(arrCuerpo)));

        for (var i = 0; i < arrFich.length; i++) {
            var objF   = arrFich[i];
            var arrDat = await leer(objF);
            var szTipo = objF.type || 'application/octet-stream';

            // The name in quotes and with no quotes inside, or the
            // header breaks and the attachment arrives with no name.
            var szNom = String(objF.name || 'adjunto').replace(/["\r\n]/g, '_');

            arrPartes.push(texto(
                '\r\n--' + szFront + '\r\n'
                + 'Content-Type: ' + szTipo.replace(/[\r\n;]/g, '') + '; name="' + szNom + '"\r\n'
                + 'Content-Transfer-Encoding: base64\r\n'
                + 'Content-Disposition: attachment; filename="' + szNom + '"\r\n\r\n'
                + b64Lineas(arrDat)));
        }

        arrPartes.push(texto('\r\n--' + szFront + '--\r\n'));

        return unir(arrPartes);
    }

    return { montar: montar };
})();
