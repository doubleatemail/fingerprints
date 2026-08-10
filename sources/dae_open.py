#!/usr/bin/env python3
"""
dae_open.py - Abre un correo puzzle en TU ordenador.

    python dae_open.py mensaje.ehead --clave mi_clave.pem

El programa saca de tu cabecera donde esta la otra pieza, se la descarga
y escribe el correo. Si ya la tienes bajada, pasasela y no se conecta a
ningun sitio:

    python dae_open.py mensaje.ehead mensaje.ebody --clave mi_clave.pem

Junta las dos piezas y escribe un fichero .eml corriente, que puedes
abrir con Thunderbird, Outlook, Apple Mail o cualquier otro programa.

POR QUE EXISTE ESTO
-------------------
Tu clave privada no sale de tu ordenador. Lo unico que este programa
llega a pedirle al servidor es la segunda pieza, y la pide por su
localizador, sin decir quien eres ni de que mensaje se trata: el
servidor no puede saberlo. Puedes leerlo entero -son doscientas
lineas- y comprobar que es verdad, cosa que no puedes hacer con una
pagina web, porque la pagina te la servimos nosotros cada vez que
entras.

Y sigue funcionando aunque doubleat.email desaparezca. Guarda las dos
piezas y tu clave, y dentro de diez anyos ese correo se seguira
abriendo. Eso es lo que convierte al protocolo '@@' en algo que no
depende de nosotros.

QUE NECESITAS
-------------
    pip install cryptography

FORMATO (para quien quiera escribir su propia version)
------------------------------------------------------
El eHead es un JSON:

    szVersion    "DAE-2"  (o "DAE-1", el formato antiguo)
    szAlgo       "A256GCM+RSA-OAEP+AONT"
    szIv         12 bytes en base64
    szTag        16 bytes en base64, el tag GCM
    nBlockSize   tamanyo del cifrado completo
    nHeadSize    cuantos bytes de ese cifrado van en el eHead
    arrEncKeys   huella de clave publica -> base64 de RSA-OAEP(clave || localizador)
    szPayload    base64 de los primeros nHeadSize bytes del cifrado

El cifrado completo es szPayload + el fichero eBody, en ese orden.

LO IMPORTANTE, Y ES EL PUNTO DEL PROTOCOLO
------------------------------------------------------
En DAE-2 la clave de 32 bytes que sale de arrEncKeys NO es la clave:
viene enmascarada. La clave de verdad se obtiene asi:

    mascara = sha256(b"DAE-AONT-v2" + cifrado_completo)
    clave   = clave_enmascarada XOR mascara

Es decir: hace falta el cifrado ENTERO, hasta el ultimo byte, solo para
averiguar la clave. A quien le falte un byte no obtiene la clave, y sin
clave no descifra nada, ni un trozo. No es que le falte potencia de
calculo: le faltan datos, y los datos que no existen no se calculan.
Se llama transformacion todo-o-nada, y es la razon por la que interceptar
una de las dos piezas no sirve absolutamente de nada.

DAE-1, el formato antiguo, no lo llevaba: su clave iba tal cual y su
cabecera incluia szChecksum, el sha256 del cifrado completo. Se sigue
abriendo para no dejar sin leer el correo ya repartido, pero con DAE-1
quien interceptase el eHead y consiguiese la clave podia leer ese trozo
del mensaje. Por eso se cambio.

Descifrado: AES-256-GCM. Las entradas de arrEncKeys se abren con tu
clave privada (RSA-OAEP con SHA-1, que es lo que usa OpenSSL por
defecto).

Los 32 bytes siguientes de esa misma entrada son el localizador del
eBody. Van ahi, cifrados, para que nadie sepa donde esta la otra pieza
sin tener tu clave privada.

Licencia: dominio publico. Copialo, cambialo, publicalo.
"""

import argparse
import base64
import urllib.request
import urllib.error
import getpass
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Falta la biblioteca 'cryptography'. Instalala con:\n\n"
             "    pip install cryptography\n")

SERVIDOR_POR_DEFECTO = "https://doubleat.email"
AGENTE = "dae_open.py/1.0 (+https://doubleat.email)"
VERSION_ACTUAL = "DAE-2"
VERSIONES_VALIDAS = ("DAE-2", "DAE-1")

# Etiqueta de dominio de la mascara todo-o-nada. Va dentro del resumen
# para que ese valor no valga para ninguna otra cosa del protocolo.
ETIQUETA_AONT = b"DAE-AONT-v2"
LONGITUD_CLAVE = 32          # AES-256
LONGITUD_LOCALIZADOR = 32


def aviso(texto):
    print(texto, file=sys.stderr)


def cargar_clave_privada(ruta, contrasena):
    """Lee la clave privada. Si esta protegida y no hay contrasena, la pide."""
    with open(ruta, "rb") as f:
        datos = f.read()

    protegida = b"ENCRYPTED" in datos.split(b"\n")[0] or b"ENCRYPTED" in datos[:200]

    if protegida and contrasena is None:
        contrasena = getpass.getpass("Contrasena de tu clave privada: ")

    try:
        return serialization.load_pem_private_key(
            datos,
            password=contrasena.encode() if contrasena else None,
        )
    except (ValueError, TypeError) as e:
        sys.exit("No se ha podido leer la clave privada: %s\n"
                 "Comprueba que es el fichero correcto y la contrasena." % e)


def abrir_entrada(clave_privada, entradas):
    """
    Prueba cada entrada de arrEncKeys hasta que una abre.

    Que fallen las demas es lo normal: un correo puede ir sellado para
    varios destinatarios y solo una entrada es la tuya.
    """
    for huella, sellado in entradas.items():
        try:
            crudo = clave_privada.decrypt(
                base64.b64decode(sellado),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
        except Exception:
            continue

        if len(crudo) == LONGITUD_CLAVE + LONGITUD_LOCALIZADOR:
            return crudo[:LONGITUD_CLAVE], crudo[LONGITUD_CLAVE:], huella

    return None, None, None


def descargar_pieza(servidor, localizador):
    """
    Pide la segunda pieza por su localizador.
    
    No se manda nada mas: ni quien eres, ni tu clave, ni de que mensaje
    se trata. El localizador es la unica credencial, y solo lo tiene
    quien ha podido abrir la cabecera.
    """
    url = "%s/ebody/%s" % (servidor.rstrip("/"), localizador.hex())
    print("Descargando la otra pieza de %s ..." % servidor)

    # Nos identificamos con nuestro nombre. No es cosmetico: el
    # user-agent que urllib pone por defecto ('Python-urllib/...') esta
    # en las listas de bots de Cloudflare y devuelve 403. Y disfrazarse
    # de navegador seria mentir en una herramienta cuyo argumento es
    # precisamente que puedes leer lo que hace.
    peticion = urllib.request.Request(url, headers={"User-Agent": AGENTE})

    try:
        with urllib.request.urlopen(peticion, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.exit("El servidor no tiene esa pieza.\n"
                     "O el mensaje ya ha cumplido su plazo y se ha borrado,\n"
                     "que en ese caso es lo que tenia que pasar.")
        sys.exit("El servidor ha respondido %s." % e.code)
    except urllib.error.URLError as e:
        sys.exit("No se ha podido conectar con %s: %s\n"
                 "Si ya tienes la pieza bajada, pasasela como segundo\n"
                 "argumento y este programa no se conectara a ningun sitio."
                 % (servidor, e.reason))


def main():
    p = argparse.ArgumentParser(
        description="Junta las dos piezas de un correo puzzle y escribe un .eml",
        epilog="Tu clave privada no sale de este ordenador.",
    )
    p.add_argument("ehead", help="la pieza que llego por correo (.ehead)")
    p.add_argument("ebody", nargs="?", default=None,
                   help="la otra pieza, si ya la tienes bajada. Si no se pone, "
                        "se descarga sola")
    p.add_argument("--clave", "-k", required=True, help="tu clave privada, en PEM")
    p.add_argument("--contrasena", "-p", default=None,
                   help="contrasena de la clave privada (si no, se pide al vuelo)")
    p.add_argument("--salida", "-o", default=None, help="fichero .eml a escribir")
    p.add_argument("--servidor", "-s", default=SERVIDOR_POR_DEFECTO,
                   help="de donde bajar la segunda pieza (por defecto %s)"
                        % SERVIDOR_POR_DEFECTO)
    p.add_argument("--guardar-pieza", action="store_true",
                   help="deja tambien en disco la pieza descargada, por si "
                        "quieres guardarla y no volver a depender del servidor")
    args = p.parse_args()

    # --- las dos piezas ---------------------------------------------
    try:
        with open(args.ehead, "rb") as f:
            cabecera = json.loads(f.read().decode("utf-8").strip())
    except (OSError, ValueError) as e:
        sys.exit("No se ha podido leer la cabecera: %s" % e)

    if cabecera.get("szVersion") not in VERSIONES_VALIDAS:
        aviso("AVISO: la cabecera dice version '%s' y esperabamos '%s'. Se sigue."
              % (cabecera.get("szVersion"), VERSION_ESPERADA))

    # --- tu clave abre la entrada que te corresponde -----------------
    clave_privada = cargar_clave_privada(args.clave, args.contrasena)
    clave_aes, localizador, huella = abrir_entrada(
        clave_privada, cabecera.get("arrEncKeys", {}))

    if clave_aes is None:
        sys.exit("Tu clave no abre este correo.\n"
                 "O no es para ti, o no es la clave que corresponde a la\n"
                 "direccion a la que llego.")

    print("Abierto con la clave de huella %s" % huella[:16])
    print("La otra pieza esta en %s" % localizador.hex()[:16])

    # --- la segunda pieza: la tienes o se baja ------------------------
    if args.ebody:
        try:
            with open(args.ebody, "rb") as f:
                cuerpo = f.read()
        except OSError as e:
            sys.exit("No se ha podido leer la segunda pieza: %s" % e)
    else:
        cuerpo = descargar_pieza(args.servidor, localizador)
        if args.guardar_pieza:
            ruta = localizador.hex() + ".ebody"
            with open(ruta, "wb") as f:
                f.write(cuerpo)
            print("Pieza guardada en %s" % ruta)

    # --- las dos piezas, una detras de otra --------------------------
    cifrado = base64.b64decode(cabecera["szPayload"]) + cuerpo

    esperado = cabecera.get("nBlockSize")
    if esperado is not None and len(cifrado) != esperado:
        aviso("AVISO: el mensaje deberia medir %s bytes y mide %d. "
              "Puede que falte parte del eBody." % (esperado, len(cifrado)))

    # DAE-1 llevaba la huella en la cabecera. Para ese formato ya no es
    # ningun secreto, asi que se comprueba y ya esta.
    checksum = cabecera.get("szChecksum")
    if checksum and hashlib.sha256(cifrado).hexdigest() != checksum:
        aviso("AVISO: la huella del mensaje no cuadra. Sigue el intento, "
              "pero algo se ha alterado o esta incompleto.")

    # --- quitar la mascara (DAE-2) ------------------------------------
    # Aqui es donde el protocolo cumple lo que promete. La clave que
    # venia en la cabecera no sirve para nada por si sola: hay que
    # deshacerla con el resumen del cifrado completo, y para eso hacen
    # falta las dos piezas enteras. Si falta un solo byte sale otra
    # clave, el descifrado de abajo falla, y no se lee nada.
    if cabecera.get("szVersion") == VERSION_ACTUAL:
        mascara = hashlib.sha256(ETIQUETA_AONT + cifrado).digest()
        clave_aes = bytes(a ^ b for a, b in zip(clave_aes, mascara))

    # --- descifrar ---------------------------------------------------
    iv = base64.b64decode(cabecera["szIv"])
    tag = base64.b64decode(cabecera["szTag"])

    try:
        # AESGCM espera el tag pegado al final del cifrado
        claro = AESGCM(clave_aes).decrypt(iv, cifrado + tag, None)
    except Exception:
        sys.exit("El mensaje no se ha podido descifrar.\n"
                 "Las piezas estan alteradas, incompletas, o no son del\n"
                 "mismo correo. Con el correo puzzle basta que falte un\n"
                 "byte de cualquiera de las dos para que no salga nada.")

    salida = args.salida or (args.ehead.rsplit(".", 1)[0] + ".eml")
    with open(salida, "wb") as f:
        f.write(claro)

    print("\nCorreo reconstruido: %s  (%d bytes)" % (salida, len(claro)))
    print("Abrelo con Thunderbird, Outlook o el programa de correo que uses.")


if __name__ == "__main__":
    main()
