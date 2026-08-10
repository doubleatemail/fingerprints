/**
 * DAE - El video de la portada, que no se carga solo
 *
 * Un iframe de YouTube puesto sin mas hace que el navegador de cada
 * visitante le pida ficheros a Google y le entregue su IP antes de que
 * nadie pulse nada. La portada es la pagina mas visitada, asi que eso
 * seria rastrear a todo el que pasa, y dejaria en falso lo que dice
 * /?page=cookies.
 *
 * Aqui no hay nada de fuera hasta que alguien pulsa. Ni siquiera la
 * miniatura: las de YouTube tambien viajan desde sus servidores, asi que
 * usar una seria el mismo problema con otra cara.
 *
 * Al pulsar se usa youtube-nocookie.com, que es lo menos malo que ofrece
 * YouTube, y se dice al lado del boton lo que va a pasar. Quien no pulsa,
 * no sale de aqui.
 */
(function () {
    'use strict';

    var objCaja  = document.getElementById('videoCaja');
    var objBoton = document.getElementById('videoPlay');
    if (!objCaja || !objBoton) { return; }

    objBoton.addEventListener('click', function () {
        var szId = objCaja.dataset.video || '';

        // Solo lo que puede ser un identificador de YouTube. Si algun dia
        // esa configuracion la toca alguien mas, que no pueda meter una
        // direccion entera y llevarse al visitante a otro sitio.
        if (!/^[A-Za-z0-9_-]{6,20}$/.test(szId)) { return; }

        var objMarco = document.createElement('iframe');
        objMarco.src = 'https://www.youtube-nocookie.com/embed/' + szId
                     + '?autoplay=1&rel=0';
        objMarco.title = objBoton.textContent.trim();
        objMarco.allow = 'accelerometer; autoplay; encrypted-media; picture-in-picture';
        objMarco.allowFullscreen = true;
        objMarco.loading = 'lazy';
        objMarco.className = 'video-marco';

        objCaja.innerHTML = '';
        objCaja.appendChild(objMarco);
    });
})();
