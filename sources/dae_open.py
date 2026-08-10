#!/usr/bin/env python3
"""
dae_open.py - Opens a puzzle email on YOUR computer.

    python dae_open.py mensaje.ehead --clave mi_clave.txt

The program pulls out of your header where the other piece is -which
piece and on which server- downloads it and writes the email. You do not
have to tell it where to look: the address is sealed inside the message.
If you already have the piece downloaded, hand it over and it will not
connect anywhere:

    python dae_open.py mensaje.ehead mensaje.ebody --clave mi_clave.txt

It joins the two pieces and writes an ordinary .eml file, which you can
open with Thunderbird, Outlook, Apple Mail or any other program.

If the email carries a PIN, add it:

    python dae_open.py mensaje.ehead --clave mi_clave.txt --pin 314159

The PIN does not travel with the email: whoever sent it has to tell it
to you by another route. Without --pin, "000000" is used, which is what
the emails that carry no real PIN are sealed with.

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

    szVersion    "DAE-5"
    szAlgo       "A256GCM+X25519+AONT+PIN+ORIGIN"
    szIv         12 bytes in base64
    szTag        16 bytes in base64, the GCM tag
    nPinIter     PBKDF2 iterations used for the PIN
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
                 || nLen(1) || origen(nLen bytes ASCII)

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
comes masked, twice. The real one is obtained like this:

    mascara     = sha256(b"DAE-AONT-v2" + cifrado_completo)
    mascara_pin = PBKDF2-HMAC-SHA256(PIN,
                                     salt = localizador, 32 RAW bytes,
                                     nPinIter, 32 bytes)
    clave       = clave_enmascarada XOR mascara XOR mascara_pin

That is: the ENTIRE ciphertext is needed, down to the last byte, just
to work out the key. Whoever is missing one byte does not get the key,
and without the key nothing is decrypted, not even a fragment. It is
not that they lack computing power: they lack data, and data that does
not exist cannot be computed. It is called an all-or-nothing transform,
and it is the reason why intercepting one of the two pieces is
absolutely useless.

The salt is the locator in its 32 RAW bytes, NOT the 64 characters of
its hexadecimal. Both seal without complaining and neither opens what
the other sealed, so it is worth checking twice.

nPinIter is read from the header and never from a constant here: the
number gets raised over time, and mail sealed before the change has to
keep opening. It is 1 when the PIN is the default "000000", where a
slow derivation would buy nothing because that PIN is public, and
600000 when the PIN is real. Anything outside 1..10000000 is refused,
so a doctored header cannot turn opening into an endless computation.

PBKDF2 and not Argon2id, which would be better against the dedicated
hardware that is exactly what attacks a short PIN: WebCrypto has no
Argon2id, and the browser has to open this same email.

There is no checksum in the header, and that absence is deliberate:
the digest of the complete ciphertext is exactly the value that takes
the mask off, so publishing it in the piece that travels by mail would
have reduced all of this to nothing. Integrity is the GCM tag's job,
and the tag covers the whole message.

The other 32 bytes of that same envelope are the eBody locator. They
go there, encrypted, so that nobody knows where the second piece is
without having your private key.

THE ORIGIN, AND WHY IT ARRIVED LATE
-----------------------------------
Behind the locator comes one byte with a length, and then that many
bytes of ASCII: the domain of the server where the second piece lives.

Until DAE-4 the envelope said WHICH piece to ask for and never WHOM to
ask, and every implementation quietly assumed the answer was its own
server. That works exactly as long as there is one server in the world.
The day a second one appeared, mail between them stopped at "the second
half is no longer available": the recipient was looking in their own
storage for a piece that had stayed in the sender's. This very file
papered over it with a hardcoded doubleat.email, which is what gave it
away.

It travels INSIDE the envelope and never in the header, on purpose. The
eHead is a file that gets forwarded, saved and copied. In the clear,
whoever intercepted the carrier mail would learn which door to knock on
for the other half; sealed, only the person who could already read the
message knows.

The length byte instead of a separator is not decoration: a separator
forces a decision about what happens when it turns up inside the data,
and that decision is where five implementations start reading five
different things. One byte holds 255 and a domain name stops at 253.

And a warning for anyone writing their own version: that domain is
attacker-supplied. Encryption proves nobody altered it on the way, not
that whoever wrote it means well. Opening a message must never become
the way to make your computer fetch a URL of somebody else's choosing.
Check it before you connect: public domain name, no IP literal, no
port, no path, no reserved TLD. See dominio_valido() below.

License: MIT. Copy it, change it, publish it, sell it.
"""

import argparse
import base64
import urllib.request
import urllib.error
import urllib.parse
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

AGENTE = "dae_open.py/1.0 (+https://doubleat.email)"
VERSION = "DAE-5"

# There is NO default server, and its absence is the point of DAE-5.
# This program used to have "https://doubleat.email" wired in, which
# worked only because there was a single server in the world: a header
# from anywhere else sent you asking the wrong machine for the piece,
# and you got a 404 that said nothing about what was wrong. The address
# now comes out of the message, sealed, where whoever wrote it put it.

# Longest a domain name can be, RFC 1035. The envelope carries the
# origin with its length in front, in one byte, which is what fits.
ORIGEN_MAX = 253

# Names that belong to nobody by definition (RFC 2606 and RFC 6761) or
# that point back at your own machine.
TLD_PROHIBIDOS = ("test", "invalid", "example", "local",
                  "localhost", "internal", "home", "lan")

# Domain label of the all-or-nothing mask. It goes inside the digest
# so that value is good for nothing else in the protocol.
ETIQUETA_AONT = b"DAE-AONT-v2"

# Domain label of the READ PROOF (06_AT_AT_PROTOCOL.md 9.bis).
# Deliberately different from the one above: both digests are computed
# over material from the same message, and without separate labels one
# could pass for the other. The spare one would be the serious case:
# whoever held the mask digest could forge the "I have read it" notice
# without having read anything.
ETIQUETA_LECTURA = b"DAE-READ-1"

# The PIN of the mail that carries no real PIN. Public on purpose: it
# is written here and in every other implementation.
PIN_DEFECTO = "000000"

# Bounds for nPinIter. The header arrives with the email and nothing
# vouches for it, so a tampered count could ask this program for an
# amount of work that never ends.
PIN_ITER_MIN = 1
PIN_ITER_MAX = 10000000

# Used ONLY when the header has no nPinIter at all, which no sealer
# produces and means the header is broken. It is not the iteration
# count of anything: a real one is always read from the header, or
# mail sealed before the number was raised would stop opening. The
# value matches what clsEBlock.php falls back to, so that a broken
# header behaves the same in both.
PIN_ITER_SI_FALTA = 600000

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


def dominio_valido(dominio):
    """Can that name be asked for the second piece?

    THE SAME RULE as clsKeyFetch::dominioValido() on the server, and it
    has to stay the same: a public domain name with its dot, no IP
    literal, no port, no path, no brackets, none of the reserved TLDs.

    THIS IS NOT COSMETIC. The origin comes out of an envelope somebody
    else sealed. That it arrived encrypted proves nobody altered it in
    transit; it proves nothing about whoever wrote it. Opening a message
    must never become the way to make your computer fetch a URL of
    somebody else's choosing: without this filter, sending you an email
    would be enough to make this program call 'localhost' or an address
    inside your network, and report back whatever came out. Refusing is
    the correct answer here, not an inconvenience.
    """
    dominio = str(dominio or "").strip().lower()

    if not dominio or len(dominio) > ORIGEN_MAX:
        return False

    etiquetas = dominio.split(".")
    if len(etiquetas) < 2:
        return False

    for etiqueta in etiquetas:
        if not etiqueta or len(etiqueta) > 63:
            return False
        if etiqueta[0] == "-" or etiqueta[-1] == "-":
            return False
        if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in etiqueta):
            return False

    # An IPv4 address would pass the test above. It does not do: the
    # piece is not asked of a number, it is asked of a name, which is
    # the only thing a certificate can vouch for.
    if all(c in "0123456789." for c in dominio):
        return False

    return etiquetas[-1] not in TLD_PROHIBIDOS


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

    What comes out of the one that opens is three things now:

        k'(32) || locator(32) || nLen(1) || origin(nLen)

    The envelope is no longer a fixed 64 bytes. The length byte rules,
    and it has to agree with what is left: an envelope that does not add
    up with itself is not interpreted as best we can, it is discarded.
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

        fijo = LONGITUD_CLAVE + LONGITUD_LOCALIZADOR
        if len(crudo) <= fijo:
            continue

        largo = crudo[fijo]
        if largo < 1 or len(crudo) != fijo + 1 + largo:
            continue

        origen = crudo[fijo + 1:].decode("ascii", "replace").strip().lower()

        return (crudo[:LONGITUD_CLAVE],
                crudo[LONGITUD_CLAVE:fijo],
                origen,
                huella)

    return None, None, None, None


def descargar_pieza(servidor, localizador):
    """
    Asks for the second piece by its locator.

    Nothing else is sent: not who you are, not your key, not which
    message it is about. The locator is the only credential, and only
    whoever has been able to open the header has it.

    'servidor' is a bare domain name, checked by dominio_valido()
    before getting here, and https is written out by hand: the address
    came out of a message somebody else wrote.
    """
    url = "https://%s/ebody/%s" % (servidor, localizador.hex())
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


def avisar_lectura(servidor, localizador, clave_aes):
    """Tells the server holding the piece that its mail has been read.

    This is what makes "destroyed on reading" actually destroy the mail
    when the reader is on a different server. Until this existed, the
    sender's row never heard about the read and the piece only died
    later, by deadline.

        token = sha256("DAE-READ-1" || k || szBodyId)
        POST https://<servidor>/ebody/read    id=...&token=...

    Only someone who recovered k can compute it, and recovering k takes
    both whole pieces plus the private key plus the PIN: exactly the
    three things needed to read, not one fewer. That is why this is not
    a remote destruction button. Knowing the locator is not enough, and
    it must never become enough.

    EVERY FAILURE IS SWALLOWED, on purpose. The mail is already
    decrypted and written to disk; refusing to finish the job because a
    third machine did not answer would be trading one promise for a
    worse one. If the notice never arrives, the piece expires by its
    deadline, which is the safety net underneath all of this and does
    not go away.
    """
    token = hashlib.sha256(
        ETIQUETA_LECTURA + clave_aes + localizador.hex().encode("ascii")
    ).hexdigest()

    datos = urllib.parse.urlencode({
        "id": localizador.hex(),
        "token": token,
    }).encode("ascii")

    # https written out by hand, same as everywhere else in this file:
    # the name came out of a message somebody else wrote, and it has
    # already gone through dominio_valido() before getting here.
    peticion = urllib.request.Request(
        "https://%s/ebody/read" % servidor, data=datos, method="POST",
        headers={
            "User-Agent": AGENTE,
            "Content-Type": "application/x-www-form-urlencoded",
        })

    try:
        with urllib.request.urlopen(peticion, timeout=5) as r:
            r.read()
        print("Avisado a %s de que este correo ya se ha leido." % servidor)
    except Exception:
        # Not even a warning. The reader has nothing to do about this
        # and it is not their problem: their mail is open.
        pass


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
    p.add_argument("--pin", default=None, metavar="NNNNNN",
                   help="el PIN del correo, si lleva. No viaja con el "
                        "mensaje: quien te lo envio tiene que decirtelo por "
                        "otro camino. Si no lo pones se prueba con 000000")
    p.add_argument("--salida", "-o", default=None, help="fichero .eml a escribir")
    p.add_argument("--servidor", "-s", default=None, metavar="DOMINIO",
                   help="forzar de que servidor se baja la segunda pieza. "
                        "NO hace falta: el mensaje ya dice donde esta, y "
                        "esto solo sirve para probar contra otra maquina")
    p.add_argument("--guardar-pieza", action="store_true",
                   help="deja tambien en disco la pieza descargada, por si "
                        "quieres guardarla y no volver a depender del servidor")
    p.add_argument("--sin-aviso", action="store_true",
                   help="no avisar al servidor de que has leido el correo. "
                        "Ese aviso es lo que hace que un mensaje 'se destruye "
                        "al leerlo' se destruya de verdad; sin el, la pieza "
                        "vive hasta que cumpla su plazo")
    args = p.parse_args()

    # A PIN that is not six digits is a warning and not an exit: it is
    # almost certainly a typo, but refusing outright would make an
    # email unopenable here on a guess about how it was sealed.
    pin = args.pin if args.pin is not None else PIN_DEFECTO
    if args.pin is not None and (len(pin) != 6
                                 or any(c not in "0123456789" for c in pin)):
        aviso("AVISO: los PIN son de 6 cifras y ese no lo es. Se prueba "
              "igualmente.")

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
    clave_aes, localizador, origen, huella = abrir_entrada(
        clave_privada, cabecera.get("arrEncKeys", {}))

    if clave_aes is None:
        sys.exit("Tu clave no abre este correo.\n"
                 "O no es para ti, o no es la clave que corresponde a la\n"
                 "direccion a la que llego.")

    print("Abierto con la clave de huella %s" % huella[:16])
    print("La otra pieza esta en %s, en %s" % (origen, localizador.hex()[:16]))

    # --- the second piece: you have it or it gets downloaded ----------
    if args.ebody:
        try:
            with open(args.ebody, "rb") as f:
                cuerpo = f.read()
        except OSError as e:
            sys.exit("No se ha podido leer la segunda pieza: %s" % e)
    else:
        # WHERE IT IS COMES FROM THE MESSAGE, not from a constant in
        # this file. --servidor is only there to point the program at a
        # test machine, and even then the name has to pass the same
        # check: neither the message nor the command line gets to send
        # this program at an address that is not a public domain name.
        donde = args.servidor or origen
        if not dominio_valido(donde):
            sys.exit("Este correo dice que su otra pieza esta en '%s',\n"
                     "y eso no es un nombre de servidor al que se le pueda\n"
                     "pedir nada: no se va a ir a buscarla ahi.\n"
                     "Si ya la tienes bajada, pasasela como segundo\n"
                     "argumento y este programa no se conectara a ningun\n"
                     "sitio." % donde)

        cuerpo = descargar_pieza(donde, localizador)
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

    # --- remove the two masks -------------------------------------------
    # This is where the protocol delivers what it promises. The key
    # that came in the header is good for nothing on its own: it has
    # to be undone with the digest of the complete ciphertext, and for
    # that both whole pieces are needed. If a single byte is missing a
    # different key comes out, the decryption below fails, and nothing
    # is read. The second mask asks for the PIN in the same way: a
    # wrong one is not detected here, it just yields another key.
    mascara = hashlib.sha256(ETIQUETA_AONT + cifrado).digest()
    clave_aes = bytes(a ^ b for a, b in zip(clave_aes, mascara))

    # From the header, never from a constant: the number gets raised
    # over time and the mail sealed before the change has to open.
    n_iter = cabecera.get("nPinIter", PIN_ITER_SI_FALTA)
    if not isinstance(n_iter, int) or isinstance(n_iter, bool) \
            or n_iter < PIN_ITER_MIN or n_iter > PIN_ITER_MAX:
        sys.exit("La cabecera de este correo esta mal: dice que el PIN se\n"
                 "deriva con %r vueltas, que no es un numero de vueltas\n"
                 "posible. O esta corrompida, o la ha tocado alguien."
                 % (n_iter,))

    # The salt is the locator RAW, not its hexadecimal.
    mascara = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"),
                                  localizador, n_iter, 32)
    clave_aes = bytes(a ^ b for a, b in zip(clave_aes, mascara))

    # --- decrypt -----------------------------------------------------
    iv = base64.b64decode(cabecera["szIv"])
    tag = base64.b64decode(cabecera["szTag"])

    try:
        # AESGCM expects the tag stuck to the end of the ciphertext
        claro = AESGCM(clave_aes).decrypt(iv, cifrado + tag, None)
    except Exception:
        # A wrong PIN and a missing byte fail in exactly the same way,
        # so the reason has to be guessed from the header. When it says
        # the mail carries a real PIN, that is far and away the likely
        # cause, and printing only "no se ha podido descifrar" would
        # leave the user with no idea what to do next.
        if n_iter > 1:
            sys.exit("Este correo lleva PIN y no se ha podido abrir.\n"
                     "%s\n"
                     "El PIN no viaja con el mensaje: quien te lo envio\n"
                     "tiene que decirtelo por otro camino, y aqui se pone\n"
                     "con --pin. Si el que has puesto es el bueno, es que\n"
                     "a alguna de las dos piezas le falta algo."
                     % ("Ponlo con --pin." if args.pin is None
                        else "El PIN que has puesto no es el de este correo."))
        sys.exit("El mensaje no se ha podido descifrar.\n"
                 "Las piezas estan alteradas, incompletas, o no son del\n"
                 "mismo correo. Con el correo puzzle basta que falte un\n"
                 "byte de cualquiera de las dos para que no salga nada.")

    salida = args.salida or (args.ehead.rsplit(".", 1)[0] + ".eml")
    with open(salida, "wb") as f:
        f.write(claro)

    # THE READ NOTICE, and it goes exactly here: the tag has verified,
    # so this is a real, complete read. Never on the download and never
    # before the tag, because a half transfer or a wrong PIN must not be
    # able to destroy a message nobody has seen.
    #
    # Only when the piece was actually downloaded. When it is handed in
    # as a file, this program promises not to connect anywhere, and that
    # promise is worth more than the notice. --sin-aviso exists for
    # whoever wants to keep it in the other case too.
    if not args.ebody and not args.sin_aviso:
        avisar_lectura(donde, localizador, clave_aes)

    print("\nCorreo reconstruido: %s  (%d bytes)" % (salida, len(claro)))
    print("Abrelo con Thunderbird, Outlook o el programa de correo que uses.")


if __name__ == "__main__":
    main()
