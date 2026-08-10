/**
 * DAE - Montar el MIME de un correo EN EL NAVEGADOR
 *
 * daemime.js sabe LEER un correo ya descifrado. Esto es lo contrario:
 * construye el mensaje, con sus adjuntos, para que lo cifre daeseal.js
 * antes de que salga de aqui.
 *
 * Sin esto el cifrado en el navegador no sirve de nada: habria que
 * mandarle el texto y los ficheros al servidor para que montase el
 * mensaje, y entonces ya los ha visto, que es justo lo que se evita.
 *
 * Lo monta clsAtAt::buildInnerMime() con PHPMailer en el servidor. Lo de
 * aqui no tiene que salir byte a byte igual que aquello: lo que tiene que
 * salir es un MIME correcto, que lo abra cualquier programa de correo y
 * que lo entienda clsMime al mostrarlo en pantalla. Hay prueba de eso.
 *
 * Se escribe a mano, sin biblioteca: son cuatro reglas y meter una
 * dependencia significaria que el usuario tiene que revisar tambien esa
 * biblioteca antes de fiarse. La pagina de comprobar publica la huella de
 * este fichero, y cuanto mas corto, mejor se lee.
 */
window.daeMimeBuild = (function () {
    'use strict';

    /**
     * Cabecera con texto que puede llevar acentos.
     *
     * Un asunto con enyes no puede viajar tal cual: el correo es de 1982
     * y las cabeceras son ASCII. Se codifica al estilo RFC 2047. Si es
     * ASCII puro se deja como esta, que es mas legible para quien mire
     * el mensaje en crudo.
     */
    function cabecera(nombre, valor) {
        valor = String(valor === undefined || valor === null ? '' : valor);

        // Nada de saltos de linea en una cabecera: ahi es por donde se
        // cuelan cabeceras falsas (inyeccion), como un Bcc que el
        // remitente no ha escrito.
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

    /** base64 en lineas de 76, como manda el formato. */
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
     * La fecha, en el formato del correo y siempre en UTC.
     *
     * A proposito: la zona horaria de quien escribe dice donde esta, y
     * este mensaje va cifrado precisamente para no contar de mas.
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
     * Monta el mensaje entero.
     *
     * @param {object} obj  {szDe, arrPara, szAsunto, szCuerpo, arrFicheros}
     *                      arrFicheros son objetos File del formulario
     * @returns {Uint8Array} el MIME listo para cifrar
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

        // Sin adjuntos no hace falta montar un multipart: un mensaje de
        // una sola parte se lee igual y ocupa menos.
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

            // El nombre entre comillas y sin comillas dentro, o se rompe
            // la cabecera y el adjunto llega sin nombre.
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
