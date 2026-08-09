# Huellas de lo que sirve doubleat.email

Este repositorio existe para que **no tengas que fiarte de nosotros**.

## El problema

[doubleat.email](https://doubleat.email) cifra el correo en tu navegador.
Eso está bien, pero tiene un agujero que conviene decir en voz alta: **el
programa que cifra te lo manda nuestro servidor** cada vez que abres la
página. Un servidor comprometido, o presionado por alguien, podría
mandarte una versión que se guarde una copia de lo que escribes, y no lo
notarías.

Esto es cierto aquí y es cierto en **cualquier** correo cifrado que
funcione dentro de un navegador. Quien te venda uno sin contártelo, te lo
está ocultando.

La web publica la huella de cada fichero que sirve. Pero esa lista la
sirve el mismo servidor, así que **no demuestra nada**: quien pueda
cambiar el programa puede cambiar también la lista.

## Para qué sirve este repositorio

Está en otro sitio, con otro dueño, y con su propio historial de cambios.
Aquí están:

- `fuentes/` — el código tal cual se sirve.
- `huellas.txt` — la huella SHA-256 de cada uno.
- `comprobar.py` — descarga los ficheros de la web y los compara con éstos.

```
python comprobar.py
```

Si alguien manipulase lo que se sirve sin poder manipular también este
repositorio, saldría.

## Comprobarlo a mano

Guarda el fichero desde tu navegador y saca su huella:

```
sha256sum daeseal.js                      # Linux, Mac
certutil -hashfile daeseal.js SHA256      # Windows
```

Compárala con la de `huellas.txt`.

## Los límites, que también se dicen

**Esto no prueba que el código sea correcto.** Prueba que lo servido es lo
publicado aquí. Que el código haga lo que dice sólo lo sabes leyéndolo, y
está escrito para poder leerse.

**Si quien controlase el servidor controlase también este repositorio,
esta comprobación no valdría.** Mira el historial de commits: lo difícil
de falsificar no es un fichero, es un pasado.

**Un fallo no siempre es un ataque.** Lo más probable, con diferencia, es
que se haya publicado una versión nueva y este repositorio no esté aún al
día. Mira la fecha del último commit antes de alarmarte.

## Si no quieres depender del navegador en absoluto

Hay dos programas que corren en tu ordenador y no necesitan nuestro
JavaScript para nada:

- `fuentes/dae_open.py` — abre un correo puzzle que hayas recibido.
- `fuentes/dae_send.py` — cifra y envía uno, con firma y adjuntos.

Se leen enteros de una sentada. Están en dominio público: cópialos,
cámbialos, redistribúyelos.

Si lo que envías es serio, usa éstos.

## El protocolo

El correo puzzle (`@@`) parte cada mensaje en dos piezas que no viajan
juntas: una va por correo y la otra se queda guardada. Y la llave del
mensaje viaja enmascarada con el resumen del cifrado entero, así que hace
falta hasta el último byte de las dos piezas para obtenerla. A quien
intercepte una no le sirve de nada: no le falta potencia de cálculo, le
faltan datos.

La especificación está en <https://doubleat.email/?page=protocol>.

---

Dominio público. Sin garantía de ninguna clase.
