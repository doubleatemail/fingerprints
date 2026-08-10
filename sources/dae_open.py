#!/usr/bin/env python3
"""
dae_open.py - Opens a puzzle email on YOUR computer.

    python dae_open.py mensaje.ehead --clave mi_clave.txt

The program pulls out of your header where the other piece is, downloads
it and writes the email. If you already have it downloaded, hand it over
and it will not connect anywhere:

    python dae_open.py mensaje.ehead mensaje.ebody --clave mi_clave.txt

It joins the two pieces and writes an ordinary .eml file, which you can
open with Thunderbird, Outlook, Apple Mail or any other program.

WHY THIS EXISTS
---------------
Your private key never leaves your computer. The only thing this
program ever asks the server for is the second piece, and it asks for
it by its locator, without saying who you are or which message it is
about: the server cannot know. You can read it whole -it is two
hundred lines- and check that this is true, which is something you
cannot do with a web page, because we are the ones serving you that
page every time you come in.

And it keeps working even if doubleat.email disappears. Keep the two
pieces and your key, and ten years from now that email will still
open. That is what turns the '@@' protocol into something that does
not depend on us.

YOUR KEY FILE
-------------
A text file holding 64 hexadecimal characters and nothing else: the 32
raw bytes of your X25519 private key. That is exactly what the webmail
writes when you export it. There is no PEM wrapper and no password,
because there is a single algorithm and a single length here and an
envelope would only make the file harder to check by eye. Guard it the
way you guard a house key.

WHAT YOU NEED
-------------
    pip install cryptography

FORMAT (for anyone who wants to write their own version)
--------------------------------------------------------
The eHead is a JSON:

    szVersion    "DAE-3"
    szAlgo       "A256GCM+X25519+AONT"
    szIv         12 bytes in base64
    szTag        16 bytes in base64, the GCM tag
    nBlockSize   size of the complete ciphertext
    nHeadSize    how many bytes of that ciphertext go in the eHead
    arrEncKeys   key fingerprint -> base64 of the sealed envelope
    szPayload    base64 of the first nHeadSize bytes of the ciphertext

The complete ciphertext is szPayload + the eBody file, in that order.

Every arrEncKeys entry is the base64 of

    eph_pub(32) || nonce(12) || AES-256-GCM ciphertext and tag

and it is opened like this, which is ECIES out of a textbook:

    compartido = X25519(tu_privada, eph_pub)
    kek        = HKDF-SHA256(compartido,
                             salt = eph_pub || tu_publica,
                             info = "DAE-3-KEK", 32 bytes)
    sobre      = AES-256-GCM-open(kek, nonce, resto)
               = clave_enmascarada(32) || localizador(32)

The salt carries BOTH public keys. Without that, the same shared
secret would give the same key in different contexts, which is how
pieces of one message get replayed into another.

The fingerprint that indexes each entry is the sha256 of the raw 32
bytes of the public key. It is only a hint: every entry is tried until
one opens, and the ones that fail are the normal case, because a
message can be sealed for several people at once.

THE IMPORTANT PART, AND IT IS THE POINT OF THE PROTOCOL
------------------------------------------------------
The 32 bytes that come out of that envelope are NOT the key: the key
comes masked. The real one is obtained like this:

    mascara = sha256(b"DAE-AONT-v2" + cifrado_completo)
    clave   = clave_enmascarada XOR mascara

That is: the ENTIRE ciphertext is needed, down to the last byte, just
to work out the key. Whoever is missing one byte does not get the key,
and without the key nothing is decrypted, not even a fragment. It is
not that they lack computing power: they lack data, and data that does
not exist cannot be computed. It is called an all-or-nothing transform,
and it is the reason why intercepting one of the two pieces is
absolutely useless.

There is no checksum in the header, and that absence is deliberate:
the digest of the complete ciphertext is exactly the value that takes
the mask off, so publishing it in the piece that travels by mail would
have reduced all of this to nothing. Integrity is the GCM tag's job,
and the tag covers the whole message.

The other 32 bytes of that same envelope are the eBody locator. They
go there, encrypted, so that nobody knows where the second piece is
without having your private key.

License: public domain. Copy it, change it, publish it.
"""

import argparse
import base64
import urllib.request
import urllib.error
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.exit("Falta la biblioteca 'cryptography'. Instalala con:\n\n"
             "    pip install cryptography\n")

SERVIDOR_POR_DEFECTO = "https://doubleat.email"
AGENTE = "dae_open.py/1.0 (+https://doubleat.email)"
VERSION = "DAE-3"

# Domain label of the all-or-nothing mask. It goes inside the digest
# so that value is good for nothing else in the protocol.
ETIQUETA_AONT = b"DAE-AONT-v2"

# Label of the HKDF. Ties the derived key to THIS use: if anything
# else is ever derived from the same shared secret it will not come
# out the same, and the two cannot be confused.
INFO_KEK = b"DAE-3-KEK"

LONGITUD_CLAVE = 32          # AES-256
LONGITUD_LOCALIZADOR = 32
LONGITUD_PUB = 32            # X25519, public and private are both 32
LONGITUD_NONCE = 12
LONGITUD_TAG = 16


def aviso(texto):
    print(texto, file=sys.stderr)


def cargar_clave_privada(ruta):
    """Reads your X25519 private key: 64 hex characters, raw bytes."""
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            texto = "".join(f.read().split())
    except OSError as e:
        sys.exit("No se ha podido leer el fichero de la clave: %s" % e)

    try:
        crudo = bytes.fromhex(texto)
    except ValueError:
        crudo = b""

    if len(crudo) != LONGITUD_PUB:
        sys.exit("Eso no es una clave privada X25519.\n"
                 "Tiene que ser un fichero de texto con 64 caracteres\n"
                 "hexadecimales, que es como te la escribe el webmail\n"
                 "cuando la exportas.")

    return x25519.X25519PrivateKey.from_private_bytes(crudo)


def abrir_entrada(clave_privada, entradas):
    """
    Tries every arrEncKeys entry until one opens.

    The rest failing is the normal thing: an email can be sealed for
    several recipients and only one entry is yours.
    """
    # Our own public key goes in the HKDF salt, and it is recomputed
    # here instead of read from the envelope: a salt supplied by
    # whoever sealed the message would let them pick the derivation
    # context.
    publica = clave_privada.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    minimo = LONGITUD_PUB + LONGITUD_NONCE + LONGITUD_TAG

    for huella, sellado in entradas.items():
        try:
            sobre = base64.b64decode(sellado)
        except Exception:
            continue

        if len(sobre) <= minimo:
            continue

        eph_pub = sobre[:LONGITUD_PUB]
        nonce = sobre[LONGITUD_PUB:LONGITUD_PUB + LONGITUD_NONCE]
        resto = sobre[LONGITUD_PUB + LONGITUD_NONCE:]

        try:
            # exchange() refuses an all-zero shared secret, which is
            # what a low-order ephemeral would produce: a point chosen
            # so the result is predictable. Landing here is not worth
            # a message, it is just one more entry that is not ours.
            compartido = clave_privada.exchange(
                x25519.X25519PublicKey.from_public_bytes(eph_pub))

            kek = HKDF(algorithm=hashes.SHA256(), length=32,
                       salt=eph_pub + publica,
                       info=INFO_KEK).derive(compartido)

            crudo = AESGCM(kek).decrypt(nonce, resto, None)
        except Exception:
            continue

        if len(crudo) == LONGITUD_CLAVE + LONGITUD_LOCALIZADOR:
            return crudo[:LONGITUD_CLAVE], crudo[LONGITUD_CLAVE:], huella

    return None, None, None


def descargar_pieza(servidor, localizador):
    """
    Asks for the second piece by its locator.

    Nothing else is sent: not who you are, not your key, not which
    message it is about. The locator is the only credential, and only
    whoever has been able to open the header has it.
    """
    url = "%s/ebody/%s" % (servidor.rstrip("/"), localizador.hex())
    print("Descargando la otra pieza de %s ..." % servidor)

    # We identify ourselves by our own name. This is not cosmetic: the
    # user-agent urllib sets by default ('Python-urllib/...') is on
    # Cloudflare's bot lists and gets a 403 back. And dressing up as a
    # browser would be lying in a tool whose whole argument is
    # precisely that you can read what it does.
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
    p.add_argument("--clave", "-k", required=True,
                   help="tu clave privada X25519: un fichero de texto con "
                        "64 caracteres hexadecimales")
    p.add_argument("--salida", "-o", default=None, help="fichero .eml a escribir")
    p.add_argument("--servidor", "-s", default=SERVIDOR_POR_DEFECTO,
                   help="de donde bajar la segunda pieza (por defecto %s)"
                        % SERVIDOR_POR_DEFECTO)
    p.add_argument("--guardar-pieza", action="store_true",
                   help="deja tambien en disco la pieza descargada, por si "
                        "quieres guardarla y no volver a depender del servidor")
    args = p.parse_args()

    # --- the two pieces ---------------------------------------------
    try:
        with open(args.ehead, "rb") as f:
            cabecera = json.loads(f.read().decode("utf-8").strip())
    except (OSError, ValueError) as e:
        sys.exit("No se ha podido leer la cabecera: %s" % e)

    if cabecera.get("szVersion") != VERSION:
        # Only an unknown format gets here, which is exactly when
        # understanding the message matters most. It is a warning and
        # not an exit because the attempt costs nothing.
        aviso("AVISO: la cabecera dice version '%s' y aqui solo se "
              "entiende '%s'. Se sigue de todas formas."
              % (cabecera.get("szVersion"), VERSION))

    # --- your key opens the entry that is yours ----------------------
    clave_privada = cargar_clave_privada(args.clave)
    clave_aes, localizador, huella = abrir_entrada(
        clave_privada, cabecera.get("arrEncKeys", {}))

    if clave_aes is None:
        sys.exit("Tu clave no abre este correo.\n"
                 "O no es para ti, o no es la clave que corresponde a la\n"
                 "direccion a la que llego.")

    print("Abierto con la clave de huella %s" % huella[:16])
    print("La otra pieza esta en %s" % localizador.hex()[:16])

    # --- the second piece: you have it or it gets downloaded ----------
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

    # --- the two pieces, one after the other -------------------------
    cifrado = base64.b64decode(cabecera["szPayload"]) + cuerpo

    esperado = cabecera.get("nBlockSize")
    if esperado is not None and len(cifrado) != esperado:
        aviso("AVISO: el mensaje deberia medir %s bytes y mide %d. "
              "Puede que falte parte del eBody." % (esperado, len(cifrado)))

    # --- remove the mask ----------------------------------------------
    # This is where the protocol delivers what it promises. The key
    # that came in the header is good for nothing on its own: it has
    # to be undone with the digest of the complete ciphertext, and for
    # that both whole pieces are needed. If a single byte is missing a
    # different key comes out, the decryption below fails, and nothing
    # is read.
    mascara = hashlib.sha256(ETIQUETA_AONT + cifrado).digest()
    clave_aes = bytes(a ^ b for a, b in zip(clave_aes, mascara))

    # --- decrypt -----------------------------------------------------
    iv = base64.b64decode(cabecera["szIv"])
    tag = base64.b64decode(cabecera["szTag"])

    try:
        # AESGCM expects the tag stuck to the end of the ciphertext
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
