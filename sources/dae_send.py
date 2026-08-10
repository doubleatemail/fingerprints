#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae_send.py - Send a puzzle email WITHOUT going through our browser

MIT licensed. Copy it, read it whole, change it, redistribute it.

------------------------------------------------------
WHAT THIS IS FOR
------------------------------------------------------
When you write from the web, the program that encrypts your email is
sent to you by our server every time you open the page. A compromised
server, or one under pressure, could send you a version that keeps a
copy of what you write, and you would not notice. That holds here and
it holds for any encrypted mail that runs inside a browser.

This program is the way out. It encrypts on YOUR computer, with code
you can read whole before running it, and all the server gets is the
two already closed pieces. It does not see your message, nor your
attachments, nor can it see them afterwards.

Its counterpart is dae_open.py, which does the same thing backwards.

------------------------------------------------------
HOW TO USE IT
------------------------------------------------------
    python dae_send.py --de ana@doubleat.email \\
                       --para luis@doubleat.email \\
                       --asunto "Hola" \\
                       --texto "Nos vemos el martes." \\
                       --adjunto contrato.pdf \\
                       --firmar mi_clave_firma.txt

It will ask you for your mailbox password, the same one as the mail. It
is not stored anywhere.

With --solo-ficheros it sends nothing: it leaves the .ehead and the
.ebody on disk so you can look at them before deciding.

------------------------------------------------------
THE PIN
------------------------------------------------------
Every message carries a PIN, and without --pin it is "000000".

That default protects NOTHING: it is public and it is written here.
It exists so that there is ONE encryption path instead of two, because
the path that gets used rarely gets tested rarely and ends up being
the one that breaks.

A real --pin does protect, and against a different attack than the
puzzle does. The puzzle protects you from whoever INTERCEPTS the mail;
it does nothing against whoever gets INTO the recipient's mailbox,
because that one has the eHead and has the key. A PIN that travels by
another channel -say a phone call- closes that hole. So tell it to
your recipient by any route other than this email, or they will not be
able to open it.

------------------------------------------------------
THE KEY FILES
------------------------------------------------------
Everything here is raw bytes in hexadecimal, in plain text files. No
PEM: there is one algorithm for each job and one length for each key,
so an envelope would buy nothing and would only make the files harder
to check by eye.

    --firmar        your Ed25519 secret key, 128 hex characters
                    (64 bytes: seed(32) || public(32))
    --clave-para    a recipient X25519 public key, 64 hex characters
    --copia         your own X25519 public key, 64 hex characters

That is the shape the webmail exports them in, and the shape the key
directory serves.

------------------------------------------------------
WHAT IT DOES INSIDE, IN ORDER
------------------------------------------------------
 1. Assembles your message in MIME, attachments included.
 2. Signs it with Ed25519, if you give it your secret key. The
    signature goes INSIDE what is encrypted: outside it would announce
    to whoever intercepts who is writing.
 3. Looks up each recipient's public key in THEIR OWN directory, at
    their own domain. Not ours: their key is not ours to serve.
 4. Encrypts everything with AES-256-GCM, with a new key for this
    message.
 5. ALL-OR-NOTHING TRANSFORM: masks that key with the digest of the
    ENTIRE ciphertext. Without both complete pieces it cannot be
    recovered, so whoever intercepts one gets nothing out of it,
    neither with time, nor with the recipient's private key.
 6. Masks it a second time with the PIN, derived slowly. Missing
    either mask, a different key comes out and nothing decrypts.
 6.bis Seals, along with the key and the locator, the DOMAIN where the
    second piece is going to live. Without it the recipient knows which
    piece to ask for and not whom to ask, and mail between two servers
    simply does not work. It goes inside the envelope and never in the
    header: whoever intercepts the carrier mail must not learn which
    door to knock on for the other half.
 7. Splits the result: 10 % goes in the eHead and the rest in the
    eBody.
 8. Delivers the two pieces. The server distributes without opening
    anything.

Steps 4, 5, 6 and 7 have to produce EXACTLY the same as clsEBlock.php and
as daeseal.js. There is a cross-check in tests/testCruzado.php: if the
three do not match byte for byte, there is mail that opens in one place
and not in another. If you change something here, pass that test.
"""

import argparse
import base64
import getpass
import hashlib
import json
import mimetypes
import os
import secrets
import sys
import urllib.error
import urllib.request
from email.message import EmailMessage

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.exit("Falta la biblioteca 'cryptography'.\n"
             "Instalala con:  pip install cryptography")

AGENTE = "dae_send.py/1.0 (+https://doubleat.email)"

VERSION       = "DAE-5"
ALGO          = "A256GCM+X25519+AONT+PIN+ORIGIN"
ETIQUETA_AONT = b"DAE-AONT-v2"

# Etiqueta de dominio de la PRUEBA DE LECTURA (06_AT_AT_PROTOCOL.md
# 9.bis). Distinta de la de arriba a proposito: los dos resumenes salen
# de material del mismo mensaje, y sin etiquetas separadas uno podria
# valer como el otro. El que sobra seria grave, porque quien tuviera el
# resumen de la mascara podria fabricar el aviso "ya lo he leido" sin
# haber leido nada.
ETIQUETA_LECTURA = b"DAE-READ-1"
MAX_HEAD      = 102400      # 100 KB
RATIO_HEAD    = 0.10        # 10 %

# Longest a domain name can be, RFC 1035. The envelope carries the
# origin with its length in front, in one byte, which is exactly what
# fits.
ORIGEN_MAX = 253

# Names that belong to nobody by definition (RFC 2606 and RFC 6761) or
# that point at the machine itself. The other implementations refuse
# them too, and they have to refuse the same ones: a mail sealed with an
# origin that one accepts and another rejects is a mail that opens in
# one place and not in the next.
TLD_PROHIBIDOS = ("test", "invalid", "example", "local",
                  "localhost", "internal", "home", "lan")

# The PIN when there is no second channel. Public on purpose: see the
# note at the top of the file. It buys a single encryption path, not
# protection.
PIN_DEFECTO = "000000"

# PBKDF2-SHA256 and not Argon2id. Argon2id would be better -it resists
# the dedicated hardware that is exactly what attacks a short PIN- but
# WebCrypto does not have it, and the browser is one of the five
# implementations that must agree with this one. Being weaker per unit
# of cost, it is compensated with iterations.
PIN_ITER = 600000

# With 000000 the slow derivation buys NOTHING: the PIN is public, so
# the attacker has nothing to try. Spending 600.000 iterations there
# would be seconds per message, sealing and opening, for zero. The
# number travels in the header, so the format does not change: only
# what it costs. It does tell whoever reads the header whether that
# mail carries a real PIN, and that is worth less than the seconds.
PIN_ITER_DEFECTO = 1

MARCA_FIRMA = "DAE-SIG1"
ALGO_FIRMA  = "Ed25519"

# Label of the HKDF. Ties the derived key to THIS use: if anything
# else is ever derived from the same shared secret it will not come
# out the same, and the two cannot be confused.
INFO_KEK = b"DAE-3-KEK"

LONGITUD_PUB = 32           # X25519, public and private are both 32

# z-base32 alphabet, the one the key directory uses. It is not the
# usual base32: it is ordered so that the characters that get confused
# when read out loud fall far away from each other.
ALFABETO_Z = "ybndrfg8ejkmcpqxot1uwisza345h769"

RAW = serialization.Encoding.Raw
RAW_PUB = serialization.PublicFormat.Raw


def aviso(texto):
    print(texto, file=sys.stderr)


# ---------------------------------------------------------------------------
#  The key directory
# ---------------------------------------------------------------------------

def zbase32(datos):
    bits = "".join(format(b, "08b") for b in datos)
    salida = ""
    for i in range(0, len(bits), 5):
        trozo = bits[i:i + 5].ljust(5, "0")
        salida += ALFABETO_Z[int(trozo, 2)]
    return salida


def dominio_de(direccion):
    """The domain of an address, lowercased, or an empty string.

    The double at sign is normalised first: addresses are written
    'luis@@otro.email' and what is wanted is 'otro.email'.
    """
    texto = str(direccion or "").strip().lower().replace("@@", "@")
    corte = texto.rfind("@")
    if corte < 0 or corte == len(texto) - 1:
        return ""
    return texto[corte + 1:]


def dominio_de_url(url):
    """The host of a server address, without scheme, port or path.

    --servidor is written as 'https://doubleat.email', and what has to
    be sealed as the origin is the bare name: the port and the path are
    fixed by the specification, and letting them travel would be letting
    whoever seals choose the URL that the recipient's machine calls.
    """
    texto = str(url or "").strip().lower()
    if "//" in texto:
        texto = texto.split("//", 1)[1]
    texto = texto.split("/", 1)[0]
    if "@" in texto:                       # user:pass@host
        texto = texto.rsplit("@", 1)[1]
    return texto.split(":", 1)[0]


def dominio_valido(dominio):
    """Can that name be asked for a key, or for the second piece?

    THE SAME RULE as clsKeyFetch::dominioValido() on the server, and it
    has to stay the same: a public domain name with its dot, no IP
    literal, no port, no path, no brackets and none of the reserved
    TLDs. When sealing, this catches a mistyped server before producing
    mail nobody can open; when opening, dae_open.py uses it for
    something more serious and says so there.
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


def hu(direccion):
    """The identifier of an address in the directory.

    Only the local part, in lowercase. What is asked for is not the
    address but its digest, so that the directory cannot be walked and
    nobody can harvest the user list by trying out names.
    """
    local = direccion.strip().lower().split("@")[0]
    return zbase32(hashlib.sha1(local.encode("utf-8")).digest())


def desde_hex(texto, longitud):
    """The raw bytes of a hex string, or None if it is not that."""
    try:
        crudo = bytes.fromhex("".join(texto.split()))
    except ValueError:
        return None
    return crudo if len(crudo) == longitud else None


def leer_clave_publica(texto):
    """Pulls the X25519 public key out of directory text.

    The directory answers in plain text, one labelled key per line
    ('curve <64 hex>' and, when there is one, 'sign <64 hex>'), because
    that parses with two lines of code in any language. A file holding
    nothing but the 64 characters is taken too: that is what somebody
    ends up with after copying a key by hand.
    """
    for linea in texto.strip().splitlines():
        partes = linea.split()
        if len(partes) == 2 and partes[0] == "curve":
            return desde_hex(partes[1], LONGITUD_PUB)
        if len(partes) == 1:
            return desde_hex(partes[0], LONGITUD_PUB)
    return None


def clave_publica_de(direccion):
    """Asks THAT PERSON'S directory for their key, not our own.

    This used to ask the server in --servidor whoever the recipient was,
    so writing to somebody on another server answered "no key published"
    even when their key was right there: we were asking the one place
    that does not have it. It is the same bug clsKeyFetch fixed on the
    server side.

    Always https, written out by hand. A key fetched over a channel that
    cannot be verified is a key that could be anybody's, and the mail
    would be sealed for them.
    """
    dominio = dominio_de(direccion)
    if not dominio_valido(dominio):
        sys.exit("'%s' no tiene un dominio al que se le pueda pedir la clave."
                 % direccion)

    url = "https://%s/.well-known/dae/hu/%s" % (dominio, hu(direccion))
    peticion = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    try:
        with urllib.request.urlopen(peticion, timeout=30) as resp:
            cuerpo = resp.read().decode("ascii", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.exit("No hay clave publicada para %s.\n"
                     "Esa direccion no puede recibir correo puzzle." % direccion)
        sys.exit("El directorio ha respondido %s al pedir la clave de %s."
                 % (e.code, direccion))
    except urllib.error.URLError as e:
        sys.exit("No se ha podido consultar el directorio: %s" % e.reason)

    publica = leer_clave_publica(cuerpo)
    if publica is None:
        sys.exit("La clave que sirve el directorio para %s no se entiende.\n"
                 "Se esperaba una X25519 en hexadecimal." % direccion)

    # The fingerprint is ALWAYS shown, and it is computed here from the
    # key that arrived instead of trusting the X-DAE-Fingerprint header:
    # whoever serves the directory could slip in their own key AND its
    # matching fingerprint. Encryption does not protect against that.
    # The only thing that does is you comparing this with your
    # recipient over another channel.
    huella = hashlib.sha256(publica).hexdigest()
    aviso("  %s -> %s" % (direccion, " ".join(
        huella.upper()[i:i + 4] for i in range(0, len(huella), 4))))
    return publica


def clave_publica_de_fichero(ruta):
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            publica = leer_clave_publica(f.read())
    except OSError as e:
        sys.exit("No se ha podido leer %s: %s" % (ruta, e))

    if publica is None:
        sys.exit("El fichero %s no tiene una clave publica X25519.\n"
                 "Se esperaban 64 caracteres hexadecimales." % ruta)
    return publica


# ---------------------------------------------------------------------------
#  The message
# ---------------------------------------------------------------------------

def montar_mime(de, para, asunto, texto, adjuntos):
    msg = EmailMessage()
    msg["From"] = de
    msg["To"] = ", ".join(para)
    msg["Subject"] = asunto
    msg.set_content(texto)

    for ruta in adjuntos:
        if not os.path.isfile(ruta):
            sys.exit("No encuentro el adjunto: %s" % ruta)
        tipo, _ = mimetypes.guess_type(ruta)
        principal, _, secundario = (tipo or "application/octet-stream").partition("/")
        with open(ruta, "rb") as f:
            msg.add_attachment(f.read(), maintype=principal,
                               subtype=secundario or "octet-stream",
                               filename=os.path.basename(ruta))

    return msg.as_bytes()


def firmar(claro, ruta_clave, remitente):
    """Wraps the message with its signature, BEFORE encrypting it.

    The signature has to end up inside the ciphertext: outside it would
    tell whoever intercepts the email who wrote it, which is exactly
    what the protocol avoids.
    """
    try:
        with open(ruta_clave, "r", encoding="utf-8") as f:
            crudo = desde_hex(f.read(), 64)
    except OSError as e:
        sys.exit("No se ha podido leer %s: %s" % (ruta_clave, e))

    if crudo is None:
        sys.exit("No he podido leer tu clave de firma.\n"
                 "Tiene que ser un fichero de texto con 128 caracteres\n"
                 "hexadecimales, que es como te la escribe el webmail.")

    # An Ed25519 secret key is seed(32) || public(32), the layout
    # libsodium uses. Signing needs only the seed; the tail is
    # recomputed and compared, which catches a truncated or swapped
    # file here instead of downstream, where it would show up as
    # signatures that nobody can verify.
    privada = ed25519.Ed25519PrivateKey.from_private_bytes(crudo[:32])
    publica = privada.public_key().public_bytes(RAW, RAW_PUB)
    if publica != crudo[32:]:
        sys.exit("Tu clave de firma no cuadra consigo misma.\n"
                 "El fichero esta cortado o cambiado.")

    firma = privada.sign(claro)

    cabecera = json.dumps({
        "szAlgo":      ALGO_FIRMA,
        "szSigner":    remitente.strip().lower(),
        "szSignerFp":  hashlib.sha256(publica).hexdigest(),
        "szSignature": base64.b64encode(firma).decode("ascii"),
    }, separators=(",", ":"))

    return (MARCA_FIRMA + "\n" + cabecera + "\n\n").encode("utf-8") + claro


# ---------------------------------------------------------------------------
#  The sealing.  THIS has to match clsEBlock.php and daeseal.js
# ---------------------------------------------------------------------------

def envolver(carga, destino):
    """Seals carga for the owner of the X25519 public key destino.

    ECIES out of a textbook, assembled by hand because WebCrypto has no
    crypto_box_seal and the browser is one of the implementations that
    must agree with this one byte for byte.

    The ephemeral is new per recipient on purpose: with a single one,
    two recipients of the same email could work out it went to both.

    Returns eph_pub(32) || nonce(12) || ciphertext and tag.
    """
    efimera = x25519.X25519PrivateKey.generate()
    eph_pub = efimera.public_key().public_bytes(RAW, RAW_PUB)

    try:
        compartido = efimera.exchange(
            x25519.X25519PublicKey.from_public_bytes(destino))
    except ValueError:
        # An all-zero shared secret means the public key was a
        # low-order point: one chosen so the result is predictable.
        # Refuse rather than encrypt under something the other side
        # already knows.
        sys.exit("Una de las claves publicas no sirve para cifrar.\n"
                 "Comprueba de donde la has sacado.")

    # The salt carries BOTH public keys. Without that, the same shared
    # secret would give the same key in different contexts, which is
    # how pieces of one message get replayed into another.
    kek = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=eph_pub + destino, info=INFO_KEK).derive(compartido)

    nonce = secrets.token_bytes(12)
    return eph_pub + nonce + AESGCM(kek).encrypt(nonce, carga, None)


def mascara_pin(pin, sal, iteraciones):
    """The mask the PIN contributes.

    Six digits are a million combinations: nothing, if they can be
    tried fast. This is what makes trying them cost, and it only holds
    up alongside the other two defences: both pieces are needed to even
    start, and the downloads of the second one are counted. Remove any
    of the three and the PIN is decoration.

    The salt is the locator, RAW, which is already random and unique
    per message: two emails with the same PIN do not give the same
    mask, so no precomputed table can be reused across messages.
    """
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), sal,
                               iteraciones, 32)


def sellar(claro, publicas, pin, origen):
    """Seals a message. origen is where the eBody is going to live.

    THE ORIGIN IS NOT OPTIONAL and has no default. Until DAE-4 the
    envelope said WHICH piece to fetch and never WHERE it lives, so
    whoever received mail from another server looked for the second half
    in their own storage, where it had never been, and got "the second
    half is no longer available" forever. Cross-server puzzle mail was
    impossible, and nobody noticed for two months because there was only
    one server to test with.

    It travels INSIDE the envelope, not in the header. The eHead is a
    file that gets forwarded, saved and copied: on its own it must not
    be a map to the other half. Whoever intercepts the carrier mail
    would otherwise know which door to knock on.

    Layout, and it has to be byte for byte what the other four
    implementations do:

        k'(32) || locator(32) || nLen(1) || origin(nLen)

    A length byte in front rather than a separator: a separator forces a
    decision about what happens when it appears inside the data, and
    that decision is exactly where five implementations start reading
    different things. One byte is enough because a domain name stops at
    253 and a byte holds 255.
    """
    if not dominio_valido(origen):
        sys.exit("'%s' no sirve como origen de la segunda pieza.\n"
                 "Tiene que ser el nombre de dominio del servidor al que\n"
                 "se entrega, sin http:// delante y sin puerto." % origen)

    clave = secrets.token_bytes(32)
    iv    = secrets.token_bytes(12)

    # AESGCM returns the tag stuck to the end; the rest of the system
    # keeps them apart, so they are split here.
    con_tag  = AESGCM(clave).encrypt(iv, claro, None)
    cifrado  = con_tag[:-16]
    tag      = con_tag[-16:]

    # ALL-OR-NOTHING TRANSFORM. The key does not travel: it travels
    # masked with the digest of the ENTIRE ciphertext. Taking the mask
    # off needs both pieces down to the last byte, so whoever
    # intercepts one gets nothing out of it. It is not that they lack
    # computing power: they lack data, and data that does not exist
    # cannot be computed.
    mascara   = hashlib.sha256(ETIQUETA_AONT + cifrado).digest()
    clave_out = bytes(a ^ b for a, b in zip(clave, mascara))

    body_id  = secrets.token_bytes(32)

    # THE PIN, second channel. It has to go into the CRYPTOGRAPHY: if
    # the server checked it before handing over the second piece, the
    # protection would depend on us behaving. Note the salt is the 32
    # RAW bytes of the locator, not its hex text: get that wrong and
    # the mail still seals, it just never opens anywhere else.
    n_iter    = PIN_ITER_DEFECTO if pin == PIN_DEFECTO else PIN_ITER
    clave_out = bytes(a ^ b for a, b in
                      zip(clave_out, mascara_pin(pin, body_id, n_iter)))

    # No longer a fixed 64 bytes: the origin is variable length and
    # carries its own length in front. Anywhere that still assumes 64
    # reads the envelope wrong.
    origen_b = origen.encode("ascii")
    semilla  = clave_out + body_id + bytes([len(origen_b)]) + origen_b

    # One curve envelope per recipient. Each carries the MASKED key,
    # the locator and the origin: those two whole, because you have to
    # know which piece to ask for and whom to ask before you have it;
    # the key not until everything is in hand.
    enc_keys = {}
    for publica in publicas:
        sellada = envolver(semilla, publica)
        enc_keys[hashlib.sha256(publica).hexdigest()] = \
            base64.b64encode(sellada).decode("ascii")

    n_block = len(cifrado)
    n_head  = min(MAX_HEAD, int(n_block * RATIO_HEAD))
    n_head  = max(1, min(n_head, n_block - 1))

    cabecera = {
        "szVersion":  VERSION,
        "szAlgo":     ALGO,
        "szIv":       base64.b64encode(iv).decode("ascii"),
        "szTag":      base64.b64encode(tag).decode("ascii"),
        # The iteration count travels here and does not live only in
        # the code: raising it tomorrow must not break the mail that
        # has already gone out.
        "nPinIter":   n_iter,
        "nBlockSize": n_block,
        "nHeadSize":  n_head,
        "arrEncKeys": enc_keys,
        # szChecksum is NOT here: it was the digest of the entire
        # ciphertext, and it is exactly the value that takes the mask
        # off. Publishing it in the piece that travels by mail would
        # reduce all of this to nothing.
        "szPayload":  base64.b64encode(cifrado[:n_head]).decode("ascii"),
    }

    # THE READ PROOF DIGEST. It has to be computed here because this
    # program is the only one that ever held the message key: the
    # server that delivers the mail never sees the message nor its key,
    # so it cannot derive this from anything that reaches it.
    #
    # Without it, a message sealed here and marked "destroyed on
    # reading" would only expire by deadline once someone on another
    # server reads it. Nobody would be told. See 06_AT_AT_PROTOCOL.md
    # 9.bis.
    #
    # What travels to the server is the DIGEST OF THE TOKEN, never the
    # token: what gets stored cannot be what gets sent, or the
    # delivering server's database would be the key to a remote
    # destruction button.
    token  = hashlib.sha256(
        ETIQUETA_LECTURA + clave + body_id.hex().encode("ascii")).hexdigest()
    prueba = hashlib.sha256(token.encode("ascii")).hexdigest()

    return (json.dumps(cabecera, separators=(",", ":")),
            cifrado[n_head:],
            body_id.hex(),
            prueba)


# ---------------------------------------------------------------------------
#  The delivery
# ---------------------------------------------------------------------------

def entregar(servidor, usuario, contrasena, para, cabecera, cuerpo, body_id,
             retencion, prueba):
    frontera = "----dae" + secrets.token_hex(16)
    partes = []

    def campo(nombre, valor):
        partes.append(
            ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
             % (frontera, nombre, valor)).encode("utf-8"))

    campo("szTo", ", ".join(para))
    campo("szHead", cabecera)
    campo("szBodyId", body_id)
    if retencion:
        campo("szRetention", retencion)
    # El resumen de la prueba de lectura. Vacio se acepta al otro lado y
    # significa "este correo no admite aviso de lectura remota": caduca
    # por plazo y no antes. Aqui siempre va lleno.
    if prueba:
        campo("szReadProof", prueba)

    partes.append(
        ("--%s\r\nContent-Disposition: form-data; name=\"ebody\"; filename=\"ebody\"\r\n"
         "Content-Type: application/octet-stream\r\n\r\n" % frontera).encode("utf-8"))
    partes.append(cuerpo)
    partes.append(("\r\n--%s--\r\n" % frontera).encode("utf-8"))

    datos = b"".join(partes)

    credencial = base64.b64encode(
        ("%s:%s" % (usuario, contrasena)).encode("utf-8")).decode("ascii")

    peticion = urllib.request.Request(
        servidor.rstrip("/") + "/?page=sealed", data=datos, method="POST",
        headers={
            "User-Agent": AGENTE,
            "Authorization": "Basic " + credencial,
            "Content-Type": "multipart/form-data; boundary=" + frontera,
        })

    try:
        with urllib.request.urlopen(peticion, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"bOk": False, "szError": "HTTP %s" % e.code}
    except urllib.error.URLError as e:
        sys.exit("No se ha podido contactar con el servidor: %s" % e.reason)


# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Cifra un correo puzzle en tu ordenador y lo envia",
        epilog="Tu mensaje no sale de aqui sin cifrar.")
    p.add_argument("--de", required=True, help="tu direccion")
    p.add_argument("--para", required=True, action="append",
                   help="destinatario; repite la opcion para varios")
    p.add_argument("--asunto", default="")
    p.add_argument("--texto", default="", help="el cuerpo del mensaje")
    p.add_argument("--texto-fichero", help="leer el cuerpo de un fichero")
    p.add_argument("--adjunto", action="append", default=[],
                   help="fichero a adjuntar; repite la opcion para varios")
    p.add_argument("--firmar", metavar="CLAVE",
                   help="tu clave privada Ed25519, un fichero de texto con "
                        "128 caracteres hexadecimales, para firmar el mensaje")
    p.add_argument("--clave-para", action="append", default=[], metavar="FICHERO",
                   help="clave publica X25519 del destinatario, 64 caracteres "
                        "hexadecimales en un fichero, en vez de pedirsela al "
                        "directorio; repite la opcion para varios")
    p.add_argument("--copia", metavar="CLAVE_PUBLICA",
                   help="tu clave publica X25519 en hexadecimal, para poder "
                        "leer tu propia copia")
    p.add_argument("--pin", metavar="NNNNNN",
                   help="PIN de 6 cifras que hara falta para abrir el correo. "
                        "Diselo a tu destinatario por otro canal, nunca en "
                        "este mismo correo. Si no lo pones se usa 000000, que "
                        "es publico y no protege de nada")
    p.add_argument("--retencion", choices=["permanent", "expiring", "ephemeral"],
                   help="cuanto vive la segunda pieza; por defecto, tu preferencia")
    p.add_argument("--servidor", default="https://doubleat.email")
    p.add_argument("--origen", metavar="DOMINIO",
                   help="dominio que se sella como sitio de la segunda "
                        "pieza. Por defecto, el de --servidor, que es "
                        "quien se la queda. Solo hace falta cambiarlo si "
                        "se entrega por un nombre y se sirve por otro")
    p.add_argument("--contrasena", help="la de tu buzon; si no, se pide al vuelo")
    p.add_argument("--solo-ficheros", metavar="PREFIJO",
                   help="no envia: deja PREFIJO.ehead y PREFIJO.ebody en disco")
    args = p.parse_args()

    # A malformed PIN is caught before anything is encrypted: past this
    # point the mistake would only show up at the far end, as mail
    # nobody can open.
    # isdigit() is not used: it says yes to digits from other scripts,
    # which would seal fine here and derive a different mask anywhere
    # that reads them as text.
    pin = args.pin if args.pin is not None else PIN_DEFECTO
    if len(pin) != 6 or any(c not in "0123456789" for c in pin):
        sys.exit("El PIN tiene que ser de 6 cifras, del 0 al 9.")

    texto = args.texto
    if args.texto_fichero:
        with open(args.texto_fichero, "r", encoding="utf-8") as f:
            texto = f.read()

    aviso("Montando el mensaje...")
    claro = montar_mime(args.de, args.para, args.asunto, texto, args.adjunto)

    if args.firmar:
        aviso("Firmando con tu clave privada...")
        claro = firmar(claro, args.firmar, args.de)
    else:
        aviso("AVISO: sin --firmar, tu destinatario vera el correo como no firmado.")

    # If the keys are handed over by hand, the directory is not
    # consulted. Whoever already has their recipient's key, checked over
    # another channel, has no reason to trust us to serve it: the
    # directory is a trust point and this is the way to sidestep it.
    if args.clave_para:
        if len(args.clave_para) != len(args.para):
            sys.exit("Has dado %d destinatarios y %d claves. Tienen que ir "
                     "en el mismo orden y ser las mismas."
                     % (len(args.para), len(args.clave_para)))
        aviso("Usando las claves que has dado, sin consultar el directorio.")
        publicas = [clave_publica_de_fichero(r) for r in args.clave_para]
    else:
        aviso("Buscando las claves publicas:")
        publicas = [clave_publica_de(d) for d in args.para]

    if args.copia:
        publicas.append(clave_publica_de_fichero(args.copia))
        aviso("  (incluida tu clave, para poder leer tu copia)")

    # WHERE THE SECOND PIECE IS GOING TO LIVE: the server this program
    # delivers to, because that is the one that keeps it. It is derived
    # from --servidor and not asked for separately, so the two can never
    # disagree: sealing one origin while delivering to another produces
    # mail whose recipient looks for the piece where it is not, and the
    # sender is told everything went fine.
    origen = args.origen or dominio_de_url(args.servidor)

    aviso("Cifrando en este ordenador...")
    cabecera, cuerpo, body_id, prueba = sellar(claro, publicas, pin, origen)
    aviso("  eHead %d bytes,  eBody %d bytes" % (len(cabecera), len(cuerpo)))

    # Only said when the PIN is real. Announcing "protegido con PIN"
    # with 000000 would be announcing a protection that does not
    # exist, and the user would stop looking for another.
    if pin != PIN_DEFECTO:
        aviso("  Lleva PIN. Diselo a tu destinatario por otro canal:")
        aviso("  si va en este mismo correo, no protege de nada.")

    if args.solo_ficheros:
        with open(args.solo_ficheros + ".ehead", "w", encoding="utf-8") as f:
            f.write(cabecera)
        with open(args.solo_ficheros + ".ebody", "wb") as f:
            f.write(cuerpo)
        print("Escritos %s.ehead y %s.ebody. No se ha enviado nada."
              % (args.solo_ficheros, args.solo_ficheros))
        return

    contrasena = args.contrasena or getpass.getpass(
        "Contrasenya de %s (la de tu correo): " % args.de)

    aviso("Entregando las dos piezas...")
    resp = entregar(args.servidor, args.de, contrasena, args.para,
                    cabecera, cuerpo, body_id, args.retencion, prueba)

    if not resp.get("bOk"):
        sys.exit("No se ha enviado: %s" % resp.get("szError", "motivo desconocido"))

    for av in resp.get("arrAvisos") or []:
        aviso("\nATENCION: la clave de %s ha cambiado desde la ultima vez."
              % av.get("szEmail", ""))
        aviso("  antes: %s" % av.get("szAntes", ""))
        aviso("  ahora: %s" % av.get("szAhora", ""))
        aviso("  Suele ser normal, pero es tambien lo que se veria si alguien")
        aviso("  estuviera suplantandole. Confirmalo por otro canal.")

    print("\nEnviado a %d destinatario(s)." % resp.get("nDestinos", len(args.para)))
    print("Tu mensaje se ha cifrado aqui: el servidor no lo ha visto.")


if __name__ == "__main__":
    main()
