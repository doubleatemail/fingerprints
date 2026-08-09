#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
comprobar.py - Contrasta lo que sirve doubleat.email con lo de este repositorio

Dominio publico. Solo usa la biblioteca estandar de Python.

------------------------------------------------------
PARA QUE SIRVE
------------------------------------------------------
doubleat.email publica en su propia web la huella de cada fichero que
sirve. Eso detecta un cambio accidental, pero no sirve de nada contra un
servidor comprometido: quien pueda cambiar el programa puede cambiar
tambien la lista de huellas. Comparar una cosa con otra que viene del
mismo sitio no demuestra nada.

Este repositorio esta en otro sitio, con otro duenyo y con su propio
historial de cambios. Este programa descarga los ficheros de la web y los
compara con los de aqui. Si alguien hubiera manipulado lo que se sirve,
sin poder manipular tambien este repositorio, saldria.

    python comprobar.py

------------------------------------------------------
LO QUE ESTE PROGRAMA NO PUEDE DECIRTE
------------------------------------------------------
Que salga todo bien significa que lo servido coincide con lo publicado
aqui. No significa que el codigo sea correcto: eso solo lo sabes
leyendolo, y esta escrito para poder leerse.

Y si quien controlase el servidor controlase tambien este repositorio,
esta comprobacion no valdria. Mira el historial de commits: lo dificil de
falsificar no es un fichero, es un pasado.
"""

import hashlib
import sys
import urllib.error
import urllib.request

SERVIDOR = "https://doubleat.email"

# Donde vive cada fichero en la web. El nombre de aqui es el de fuentes/.
DONDE = {
    "daeseal.js":    "/assets/js/daeseal.js",
    "daecrypto.js":  "/assets/js/daecrypto.js",
    "daemime.js":    "/assets/js/daemime.js",
    "daemimebuild.js": "/assets/js/daemimebuild.js",
    "daecompose.js": "/assets/js/daecompose.js",
    "selfread.js":   "/assets/js/selfread.js",
    "webmail.js":    "/assets/js/webmail.js",
    "dae_open.py":   "/assets/tools/dae_open.py",
    "dae_send.py":   "/assets/tools/dae_send.py",
}


def huellas_locales():
    esperadas = {}
    with open("huellas.txt", "r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            huella, _, nombre = linea.partition(" ")
            esperadas[nombre.strip().lstrip("*")] = huella
    return esperadas


def bajar(ruta):
    # Un parametro distinto en cada peticion para que ninguna cache
    # intermedia nos devuelva algo viejo: se comprueba lo que se sirve
    # AHORA, no lo que se sirvio hace cuatro horas.
    url = "%s%s?comprobar=1" % (SERVIDOR, ruta)
    peticion = urllib.request.Request(
        url, headers={"User-Agent": "comprobar.py (+doubleat.email)",
                      "Cache-Control": "no-cache"})
    with urllib.request.urlopen(peticion, timeout=60) as resp:
        return resp.read()


def main():
    try:
        esperadas = huellas_locales()
    except FileNotFoundError:
        sys.exit("No encuentro huellas.txt. Ejecuta esto dentro del repositorio.")

    fallos = 0
    faltan = 0

    print("Comparando lo que sirve %s con lo publicado aqui:\n" % SERVIDOR)

    for nombre, ruta in DONDE.items():
        if nombre not in esperadas:
            print("  ?  %-16s no esta en huellas.txt" % nombre)
            faltan += 1
            continue

        try:
            datos = bajar(ruta)
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            print("  ?  %-16s no se ha podido descargar (%s)" % (nombre, e))
            faltan += 1
            continue

        real = hashlib.sha256(datos).hexdigest()
        if real == esperadas[nombre]:
            print("  OK %-16s coincide" % nombre)
        else:
            fallos += 1
            print("  NO %-16s NO COINCIDE" % nombre)
            print("       aqui:    %s" % esperadas[nombre])
            print("       servido: %s" % real)

    print()
    if fallos:
        print("%d fichero(s) NO coinciden." % fallos)
        print()
        print("Antes de alarmarte: lo mas probable es que hayan publicado una")
        print("version nueva y este repositorio aun no este al dia. Mira la")
        print("fecha del ultimo commit.")
        print()
        print("Si el repositorio esta al dia y aun asi no coincide, hay algo")
        print("que explicar. No envies nada delicado desde la web hasta")
        print("saber que pasa: usa dae_send.py y dae_open.py, que corren en")
        print("tu ordenador.")
        sys.exit(1)

    if faltan:
        print("Todo lo que se ha podido comprobar coincide, pero %d fichero(s)"
              " no se han podido mirar." % faltan)
        sys.exit(2)

    print("Todo coincide con lo publicado en este repositorio.")
    print()
    print("Ojo con lo que esto significa: que lo servido es lo publicado")
    print("aqui. No que el codigo sea correcto. Eso solo lo sabes leyendolo.")


if __name__ == "__main__":
    main()
