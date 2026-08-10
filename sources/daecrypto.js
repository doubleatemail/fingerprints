/**
 * DAE - Reading puzzle mail in self custody
 *
 * This is where self custody stops being a promise: the private key is
 * NOT on our servers, so the message is decrypted in the browser of
 * whoever receives it. We cannot read it, and this is what makes it
 * true and not a marketing line.
 *
 * What it does, in order:
 *
 *   1. Opens the .daekey file with the password the user puts in. It is
 *      our own simple format --PBKDF2 + AES-256-GCM over the two
 *      private keys-- because WebCrypto cannot open a protected PKCS#8:
 *      it does not implement PBES2. That is why the usual .pem is no
 *      good.
 *   2. With that key it opens one arrEncKeys entry of the eHead and
 *      takes out three things: the AES key of the message, the locator
 *      of the other piece, and the server where that piece lives.
 *   3. Asks for that piece at https://<origen>/ebody/<locator>. The
 *      server does not get who is asking nor which message it is about:
 *      it cannot know.
 *   4. Puts the two together, decrypts with AES-256-GCM, checks the tag.
 *
 * Solo se abre DAE-5. Los formatos anteriores se borraron enteros el
 * 2026-08-10: no habia un solo correo real en ellos, y cargar para
 * siempre con varios caminos de descifrado para nadie era pagar por
 * nada. Ver clsEBlock.php y 06_AT_AT_PROTOCOL.md, secciones 3.ter,
 * 3.quater y 3.quinquies.
 *
 * The decrypted key lives in memory and only while the tab lasts. It is
 * not saved in localStorage nor in a cookie on purpose: what is not
 * written down nobody takes away.
 */

window.daeCrypto = (function () {
    'use strict';

    var objFirma = null;      // la Ed25519, para firmar
    var objClave = null;      // la X25519, CryptoKey en memoria y nada mas
    var arrMiPub = null;      // nuestra publica, hace falta para la sal
    var szQuien  = '';

    // Sigue diciendo DAE-3 y NO es un despiste: la etiqueta ata la
    // derivacion al sobre de curva, que en DAE-5 no ha cambiado. Tocarla
    // dejaria ilegible todo el correo ya enviado a cambio de nada.
    var INFO_KEK  = 'DAE-3-KEK';
    var LEN_PRIV  = 32;
    var LEN_PUB   = 32;
    var LEN_NONCE = 12;
    var LEN_TAG   = 16;

    // El PIN va SIEMPRE. Cuando no hay segundo canal es este, que es
    // publico y no protege de nada: esta para que haya un solo camino de
    // descifrado en lugar de dos.
    var PIN_DEFECTO = '000000';

    // Limites del nPinIter que llega en la cabecera. Es un numero de
    // fuera: un cero deja el PIN en nada y un absurdo cuelga la pestanya
    // hasta que la maten.
    var PIN_ITER_MIN = 1;
    var PIN_ITER_MAX = 10000000;

    // Maximo de un nombre de dominio, RFC 1035. El sobre lo trae con su
    // longitud delante, en un byte, que es justo lo que cabe.
    var ORIGEN_MAX = 253;

    /**
     * Envoltura PKCS#8 minima para una privada de curva.
     *
     * WebCrypto no importa privadas de X25519 ni de Ed25519 en crudo:
     * 'raw' solo vale para publicas. Asi que hay que vestir los 32 bytes
     * con el DER que si acepta. Los dos prefijos son iguales salvo el
     * byte que dice de que curva es: 6e para X25519, 70 para Ed25519.
     */
    var DER_X25519  = '302e020100300506032b656e04220420';
    var DER_ED25519 = '302e020100300506032b657004220420';

    function bytes(sz) {
        var arr = new Uint8Array(sz.length);
        for (var i = 0; i < sz.length; i++) { arr[i] = sz.charCodeAt(i) & 0xff; }
        return arr;
    }

    function deB64(sz) {
        return bytes(atob(String(sz).replace(/\s+/g, '')));
    }

    function deHex(sz) {
        var arr = new Uint8Array(sz.length / 2);
        for (var i = 0; i < arr.length; i++) {
            arr[i] = parseInt(sz.substr(i * 2, 2), 16);
        }
        return arr;
    }

    function hex(arrBytes) {
        var sz = '';
        for (var i = 0; i < arrBytes.length; i++) {
            sz += ('0' + arrBytes[i].toString(16)).slice(-2);
        }
        return sz;
    }

    function unir(arrA, arrB) {
        var arrOut = new Uint8Array(arrA.length + arrB.length);
        arrOut.set(arrA, 0);
        arrOut.set(arrB, arrA.length);
        return arrOut;
    }

    /**
     * A ese nombre se le puede pedir la otra pieza?
     *
     * MISMA REGLA que clsKeyFetch::dominioValido() en el servidor, y
     * repetida aqui porque este fichero se carga solo en la pagina de
     * leer, sin daeseal.js: hacerlos depender el uno del otro dejaria
     * media aplicacion sin validar.
     *
     * ESTO NO ES COSMETICA. El origen sale de un sobre que ha sellado
     * OTRA PERSONA. Que venga cifrado demuestra que nadie lo ha tocado
     * por el camino, no que quien lo escribio sea de fiar. Abrir un
     * mensaje no puede convertirse en la manera de que el navegador de
     * quien lee pida una URL elegida por quien escribe: sin este filtro,
     * mandar un correo bastaria para que la pestanya de la victima
     * llamara a "localhost" o a una direccion de su red interna. Se
     * exige nombre de dominio publico, sin IP, sin puerto, sin ruta y
     * sin los TLD reservados que por definicion no son de nadie.
     */
    function dominioValido(szDominio) {
        szDominio = String(szDominio || '').trim().toLowerCase();

        if (szDominio === '' || szDominio.length > ORIGEN_MAX) { return false; }

        if (!/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/
                .test(szDominio)) {
            return false;
        }

        if (/^[0-9.]+$/.test(szDominio)) { return false; }

        var arrProhibidos = ['test', 'invalid', 'example', 'local',
                             'localhost', 'internal', 'home', 'lan'];
        var szTld = szDominio.split('.').pop();

        return arrProhibidos.indexOf(szTld) < 0;
    }

    /** Is there a key loaded in this tab? */
    function lista() { return objClave !== null; }

    function duenyo() { return szQuien; }

    /**
     * Nuestra publica X25519, que WebCrypto no sabe sacar de la privada.
     *
     * Se calcula como esta definida: la privada por el punto base de la
     * curva, que es el 9. Hace falta para reconstruir la sal del HKDF, y
     * tiene que ser LA NUESTRA y no una que venga en el sobre: si
     * viniera de fuera, el atacante elegiria el contexto de derivacion.
     */
    async function miPublica(objPriv) {
        var arrBase = new Uint8Array(32);
        arrBase[0] = 9;
        var objBase = await crypto.subtle.importKey(
            'raw', arrBase, { name: 'X25519' }, false, []);
        return new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'X25519', public: objBase }, objPriv, 256));
    }

    /**
     * Opens the .daekey and leaves the key ready for this tab.
     *
     * @param {string} szJson  contents of the file
     * @param {string} szFrase password the user put in when exporting
     */
    async function cargar(szJson, szFrase) {
        var objSobre;
        try {
            objSobre = JSON.parse(szJson);
        } catch (e) {
            throw new Error('formato');
        }

        // Solo DAE-KEY-2. El 1 llevaba dentro un PKCS#8 de RSA y aqui ya
        // no queda nada que sepa leer eso, asi que se rechaza de frente:
        // decir "formato" es mas honesto que intentarlo y morir luego
        // con un error que no explica nada.
        if (!objSobre || objSobre.szFormato !== 'DAE-KEY-2') {
            throw new Error('formato');
        }

        // PBKDF2 over the password, with the parameters that come inside
        var objBase = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(szFrase), 'PBKDF2', false, ['deriveKey']);

        var objEnvoltura = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: deB64(objSobre.szSalt),
                iterations: objSobre.nIter,
                hash: 'SHA-256'
            },
            objBase,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']);

        var arrCrudo;
        try {
            arrCrudo = new Uint8Array(await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: deB64(objSobre.szIv) },
                objEnvoltura,
                deB64(objSobre.szClave)));
        } catch (e) {
            // The GCM tag does not add up: that is not the password
            throw new Error('frase');
        }

        // Dentro va un JSON con las dos privadas en hexadecimal, cada
        // una con su nombre. Son dos llaves y no una convertida porque
        // WebCrypto no sabe pasar de Ed25519 a X25519 --libsodium si-- y
        // pedirselo al servidor seria depender de el justo en la
        // operacion que se quiere sacar de ahi.
        //
        // Van con nombre y no pegadas una detras de otra porque asi el
        // sobre dice lo que lleva. Antes esto se resolvia mirando cuanto
        // media el bulto, y adivinar el significado de una llave por su
        // longitud es la clase de cosa que acierta hasta el dia que no.
        var objDentro;
        try {
            objDentro = JSON.parse(new TextDecoder().decode(arrCrudo));
        } catch (e) {
            throw new Error('formato');
        }

        // La de cifrar son 32 bytes y la de firmar 64: la secreta de
        // libsodium, que es semilla(32) seguida de la publica(32).
        // Se comprueban las dos longitudes y que sea hexadecimal de
        // verdad; deHex no protesta ante una letra rara, deja un NaN
        // dentro del array y la llave saldria en silencio equivocada.
        var szCurve = objDentro && objDentro.szPrivCurve;
        var szSign  = objDentro && objDentro.szPrivSign;
        var reHex   = /^[0-9a-fA-F]+$/;

        if (typeof szCurve !== 'string' || typeof szSign !== 'string' ||
            szCurve.length !== LEN_PRIV * 2 || szSign.length !== LEN_PRIV * 4 ||
            !reHex.test(szCurve) || !reHex.test(szSign)) {
            throw new Error('formato');
        }

        var arrCurve = deHex(szCurve);
        var arrSign  = deHex(szSign);

        try {
            objClave = await crypto.subtle.importKey(
                'pkcs8',
                unir(deHex(DER_X25519), arrCurve),
                { name: 'X25519' }, false, ['deriveBits']);
            arrMiPub = await miPublica(objClave);
        } catch (e) {
            // Navegador sin curva. Se para aqui y se dice: seguir por
            // otro camino seria ensenyar basura como si fuera el correo.
            objClave = null;
            arrMiPub = null;
            throw new Error('sin_curva');
        }

        // La OTRA llave, importada aparte para firmar. WebCrypto no deja
        // usar una llave de descifrado para firmar, y hace bien:
        // separar para que sirve cada una evita los ataques en los que
        // se hace firmar algo a quien creia estar descifrando.
        //
        // Del bloque de firma solo entra la primera mitad: WebCrypto
        // quiere la semilla, y la publica que libsodium pega detras la
        // sabe recalcular sola.
        try {
            objFirma = await crypto.subtle.importKey(
                'pkcs8',
                unir(deHex(DER_ED25519), arrSign.slice(0, LEN_PRIV)),
                { name: 'Ed25519' }, false, ['sign']);
        } catch (e) {
            // No poder firmar no impide leer, que es a lo que se venia.
            // Se sigue sin firma y ya esta.
            objFirma = null;
        }

        szQuien = objSobre.szEmail || '';
        return szQuien;
    }

    /** Forgets the key. Called on the way out. */
    function olvidar() {
        objClave = null;
        objFirma = null;
        arrMiPub = null;
        szQuien  = '';
    }

    /** True if the loaded key can also sign. */
    function puedeFirmar() { return objFirma !== null; }

    /**
     * Signs some bytes with the loaded key.
     *
     * Returns the raw signature. The caller assembles the envelope,
     * because the envelope format is the protocol's business and not
     * the cryptography's.
     */
    async function firmar(arrDatos) {
        if (!objFirma) { throw new Error('sin_clave_de_firma'); }
        return new Uint8Array(await crypto.subtle.sign(
            { name: 'Ed25519' }, objFirma, arrDatos));
    }

    /**
     * Abre un sobre de curva con nuestra privada.
     *
     * Devuelve null en cualquier fallo, y eso incluye "este sobre no era
     * para mi": un mensaje puede ir sellado para varios y probar todas
     * las entradas es lo normal, no un error que haya que contar.
     *
     * @param {Uint8Array} arrSobre  eph_pub(32) || nonce(12) || cif+tag
     */
    async function desenvolver(arrSobre) {
        if (arrSobre.length <= LEN_PUB + LEN_NONCE + LEN_TAG) { return null; }

        var arrEphPub = arrSobre.slice(0, LEN_PUB);
        var arrNonce  = arrSobre.slice(LEN_PUB, LEN_PUB + LEN_NONCE);
        var arrResto  = arrSobre.slice(LEN_PUB + LEN_NONCE);

        try {
            var objEph = await crypto.subtle.importKey(
                'raw', arrEphPub, { name: 'X25519' }, false, []);

            var arrCompartido = await crypto.subtle.deriveBits(
                { name: 'X25519', public: objEph }, objClave, 256);

            var objIkm = await crypto.subtle.importKey(
                'raw', arrCompartido, 'HKDF', false, ['deriveBits']);

            var arrKek = new Uint8Array(await crypto.subtle.deriveBits({
                name: 'HKDF',
                hash: 'SHA-256',
                salt: unir(arrEphPub, arrMiPub),
                info: new TextEncoder().encode(INFO_KEK)
            }, objIkm, 256));

            var objKek = await crypto.subtle.importKey(
                'raw', arrKek, { name: 'AES-GCM' }, false, ['decrypt']);

            // El tag ya viene pegado al final, que es como lo quiere
            // WebCrypto. No hay nada que recolocar.
            return new Uint8Array(await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: arrNonce, tagLength: 128 },
                objKek, arrResto));
        } catch (e) {
            return null;
        }
    }

    /**
     * La mascara que aporta el PIN.
     *
     * PBKDF2-SHA256 y no Argon2id: WebCrypto no tiene Argon2id, y este
     * fichero ES el navegador. Con Argon2id no se podria abrir nada
     * aqui, asi que no se "mejora" sin cambiar antes las cinco
     * implementaciones a la vez.
     *
     * La sal son los 32 bytes CRUDOS del localizador, no su texto
     * hexadecimal. Sale del sobre de curva ya en binario y asi entra;
     * pasarlo a hexadecimal daria otra mascara y nada abriria.
     *
     * @param {string}     szPin  el PIN que ha escrito la persona
     * @param {Uint8Array} arrSal los 32 bytes del localizador
     * @param {number}     nIter  iteraciones, leidas de la cabecera
     * @returns {Uint8Array} 32 bytes
     */
    async function mascaraPin(szPin, arrSal, nIter) {
        var objBase = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(szPin), 'PBKDF2',
            false, ['deriveBits']);

        return new Uint8Array(await crypto.subtle.deriveBits({
            name: 'PBKDF2',
            salt: arrSal,
            iterations: nIter,
            hash: 'SHA-256'
        }, objBase, 256));
    }

    /**
     * Puts the two pieces together and returns the MIME in the clear.
     *
     * Un PIN equivocado no se distingue de una pieza alterada, y es a
     * proposito: las dos cosas dan otra clave y mueren en la etiqueta
     * GCM. Quien llame decide como lo cuenta.
     *
     * szBase ya NO decide de donde se baja la segunda pieza: eso lo dice
     * el propio mensaje desde DAE-5. Se queda como forzado para los
     * tests y para quien tenga un servidor de pruebas, y cuando va vacio
     * -que es siempre en la aplicacion- manda el origen sellado.
     *
     * @param {string} szHead  the eHead, just as it arrived (JSON)
     * @param {string} szBase  forzado para pruebas; vacio en produccion
     * @param {string} [szPin] el segundo canal, si el correo lo lleva
     */
    async function abrir(szHead, szBase, szPin) {
        if (!objClave) { throw new Error('sin_clave'); }

        if (szPin === undefined || szPin === null || szPin === '') {
            szPin = PIN_DEFECTO;
        }

        var objHead;
        try {
            objHead = JSON.parse(szHead);
        } catch (e) {
            throw new Error('cabecera');
        }

        // Una version que no sea DAE-5 no se intenta. Antes habia cuatro
        // ramas mas y ya no existen; adivinar el formato seria sacar una
        // llave equivocada y llamarlo "alterado".
        if (objHead.szVersion !== 'DAE-5') { throw new Error('cabecera'); }

        // Las iteraciones se leen de la cabecera y NUNCA de una
        // constante: un correo sellado antes de subirlas tiene que
        // seguir abriendose. Se comprueba el rango porque el numero
        // viene de fuera y aqui se convierte en tiempo de CPU.
        var nIter = Number(objHead.nPinIter);
        if (!Number.isInteger(nIter) ||
            nIter < PIN_ITER_MIN || nIter > PIN_ITER_MAX) {
            throw new Error('cabecera');
        }

        // Every entry gets tried: a message can go sealed for several
        // recipients and only one of them is ours. The rest failing is
        // the normal thing.
        // El sobre ya NO mide 64 bytes fijos: detras del localizador va
        // la longitud del origen en un byte y el origen. El minimo son
        // 65 y el byte de longitud tiene que cuadrar con lo que queda; un
        // sobre que no cuadre consigo mismo no se interpreta "lo mejor
        // posible", se descarta como si no fuera nuestro.
        var arrAbierta = null;
        var arrEnc = objHead.arrEncKeys || {};
        for (var szHuella in arrEnc) {
            if (!Object.prototype.hasOwnProperty.call(arrEnc, szHuella)) { continue; }
            var arrCrudo = await desenvolver(deB64(arrEnc[szHuella]));
            if (arrCrudo && arrCrudo.length > 65
                && arrCrudo.length === 65 + arrCrudo[64]) {
                arrAbierta = arrCrudo;
                break;
            }
        }

        if (!arrAbierta) { throw new Error('no_es_para_ti'); }

        var arrClaveAes = arrAbierta.slice(0, 32);

        // Dos formas del mismo dato, y hacen falta las dos: la URL pide
        // el hexadecimal y la sal del PIN quiere los bytes crudos. Se
        // separan aqui para que nadie enchufe el texto donde va el
        // binario, que es el fallo que rompe la interoperabilidad sin
        // dar la cara.
        var arrLocaliza = arrAbierta.slice(32, 64);
        var szLocaliza  = hex(arrLocaliza);

        // Y el tercer campo: en que servidor vive la otra mitad. Sin
        // esto, un mensaje de otro dominio se buscaba aqui y no aparecia
        // nunca.
        var szOrigen = new TextDecoder().decode(arrAbierta.slice(65))
                           .trim().toLowerCase();

        // La direccion a la que se va a llamar la ha escrito quien
        // envio el correo. Ver dominioValido(): abrir un mensaje no
        // puede ser la manera de que esta pestanya pida una URL elegida
        // por otro.
        var szDonde = String(szBase || '');
        if (szDonde === '') {
            if (!dominioValido(szOrigen)) { throw new Error('origen_malo'); }
            szDonde = 'https://' + szOrigen;
        }

        // The second piece. The locator IS the credential.
        var objResp = await fetch(szDonde + '/ebody/' + szLocaliza, { credentials: 'omit' });
        if (!objResp.ok) {
            throw new Error(objResp.status === 404 ? 'pieza_no_esta' : 'pieza_error');
        }
        var arrBody = new Uint8Array(await objResp.arrayBuffer());

        // The full ciphertext: the two pieces, without the tag yet.
        var arrPayload = deB64(objHead.szPayload);
        var arrTag     = deB64(objHead.szTag);
        var arrCifrado = new Uint8Array(arrPayload.length + arrBody.length);
        arrCifrado.set(arrPayload, 0);
        arrCifrado.set(arrBody, arrPayload.length);

        // ALL-OR-NOTHING TRANSFORM. The key that came in the header is
        // not the key: it comes masked with the digest of the WHOLE
        // ciphertext. Here the mask is taken off, and it can only be
        // done because both pieces are already here. If one byte were
        // missing another key would come out and the decrypt below would
        // fail, without letting one chunk of the message be read.
        var arrEtiqueta = new TextEncoder().encode('DAE-AONT-v2');
        var arrParaHash = new Uint8Array(arrEtiqueta.length + arrCifrado.length);
        arrParaHash.set(arrEtiqueta, 0);
        arrParaHash.set(arrCifrado, arrEtiqueta.length);

        var arrMascara = new Uint8Array(
            await crypto.subtle.digest('SHA-256', arrParaHash));
        for (var i = 0; i < arrClaveAes.length; i++) {
            arrClaveAes[i] ^= arrMascara[i];
        }

        // Y la segunda mascara, la del PIN. Son dos defensas distintas:
        // la de arriba exige tener las dos piezas enteras, esta exige
        // saber algo que llego por otro camino. Faltando cualquiera de
        // las dos sale otra clave y no se descifra nada.
        var arrPin = await mascaraPin(szPin, arrLocaliza, nIter);
        for (var q = 0; q < arrClaveAes.length; q++) {
            arrClaveAes[q] ^= arrPin[q];
        }

        // And now the tag stuck at the end, the way WebCrypto expects.
        var arrTodo = new Uint8Array(arrCifrado.length + arrTag.length);
        arrTodo.set(arrCifrado, 0);
        arrTodo.set(arrTag, arrCifrado.length);

        var objAes = await crypto.subtle.importKey(
            'raw', arrClaveAes, { name: 'AES-GCM' }, false, ['decrypt']);

        var arrClaro;
        try {
            arrClaro = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: deB64(objHead.szIv), tagLength: 128 },
                objAes, arrTodo);
        } catch (e) {
            // The tag does not add up: pieces altered or incomplete
            throw new Error('alterado');
        }

        return window.daeMime.texto(new Uint8Array(arrClaro));
    }

    return {
        cargar:      cargar,
        firmar:      firmar,
        puedeFirmar: puedeFirmar,
        abrir:    abrir,
        // Se saca para los tests: tiene que decir exactamente lo mismo
        // que clsKeyFetch::dominioValido() en el servidor.
        dominioValido: dominioValido,
        lista:    lista,
        duenyo:   duenyo,
        olvidar:  olvidar
    };
})();
