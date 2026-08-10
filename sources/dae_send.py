#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae_send.py - Send a puzzle email WITHOUT going through our browser

Public domain. Copy it, read it whole, change it, redistribute it.

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
                       --firmar mi_clave_privada.pem

It will ask you for your mailbox password, the same one as the mail. It
is not stored anywhere.

With --solo-ficheros it sends nothing: it leaves the .ehead and the
.ebody on disk so you can look at them before deciding.

------------------------------------------------------
WHAT IT DOES INSIDE, IN ORDER
------------------------------------------------------
 1. Assembles your message in MIME, attachments included.
 2. Signs it, if you give it your private key. The signature goes
    INSIDE what is encrypted: outside it would announce to whoever
    intercepts who is writing.
 3. Looks up each recipient's public key in the directory.
 4. Encrypts everything with AES-256-GCM, with a new key for this
    message.
 5. ALL-OR-NOTHING TRANSFORM: masks that key with the digest of the
    ENTIRE ciphertext. Without both complete pieces it cannot be
    recovered, so whoever intercepts one gets nothing out of it,
    neither with time, nor with the recipient's private key.
 6. Splits the result: 10 % goes in the eHead and the rest in the
    eBody.
 7. Delivers the two pieces. The server distributes without opening
    anything.

Steps 4, 5 and 6 have to produce EXACTLY the same as clsEBlock.php and
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
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Falta la biblioteca 'cryptography'.\n"
             "Instalala con:  pip install cryptography")

AGENTE = "dae_send.py/1.0 (+https://doubleat.email)"

VERSION       = "DAE-2"
ALGO          = "A256GCM+RSA-OAEP+AONT"
ETIQUETA_AONT = b"DAE-AONT-v2"
MAX_HEAD      = 102400      # 100 KB
RATIO_HEAD    = 0.10        # 10 %

MARCA_FIRMA = "DAE-SIG1"
ALGO_FIRMA  = "RSA-SHA256"

# z-base32 alphabet, the one the key directory uses. It is not the
# usual base32: it is ordered so that the characters that get confused
# when read out loud fall far away from each other.
ALFABETO_Z = "ybndrfg8ejkmcpqxot1uwisza345h769"


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


def hu(direccion):
    """The identifier of an address in the directory.

    Only the local part, in lowercase. What is asked for is not the
    address but its digest, so that the directory cannot be walked and
    nobody can harvest the user list by trying out names.
    """
    local = direccion.strip().lower().split("@")[0]
    return zbase32(hashlib.sha1(local.encode("utf-8")).digest())


def clave_publica_de(servidor, direccion):
    url = "%s/.well-known/dae/hu/%s" % (servidor.rstrip("/"), hu(direccion))
    peticion = urllib.request.Request(url, headers={"User-Agent": AGENTE})
    try:
        with urllib.request.urlopen(peticion, timeout=30) as resp:
            pem = resp.read().decode("ascii")
            huella = resp.headers.get("X-DAE-Fingerprint", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.exit("No hay clave publicada para %s.\n"
                     "Esa direccion no puede recibir correo puzzle." % direccion)
        sys.exit("El directorio ha respondido %s al pedir la clave de %s."
                 % (e.code, direccion))
    except urllib.error.URLError as e:
        sys.exit("No se ha podido consultar el directorio: %s" % e.reason)

    # The fingerprint is ALWAYS shown. Whoever serves the directory
    # could slip in their own key, and encryption does not protect
    # against that: the only thing that does is you comparing it with
    # your recipient over another channel.
    if huella:
        aviso("  %s -> %s" % (direccion, " ".join(
            huella.upper()[i:i + 4] for i in range(0, len(huella), 4))))
    return pem


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


def firmar(claro, ruta_clave, remitente, contrasena):
    """Wraps the message with its signature, BEFORE encrypting it.

    The signature has to end up inside the ciphertext: outside it would
    tell whoever intercepts the email who wrote it, which is exactly
    what the protocol avoids.
    """
    with open(ruta_clave, "rb") as f:
        datos = f.read()

    try:
        privada = serialization.load_pem_private_key(
            datos, password=contrasena.encode("utf-8") if contrasena else None)
    except (ValueError, TypeError):
        sys.exit("No he podido abrir tu clave privada.\n"
                 "Si tiene contrasenya, pasala con --clave-contrasena.")

    firma = privada.sign(claro, padding.PKCS1v15(), hashes.SHA256())

    publica_der = privada.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    cabecera = json.dumps({
        "szAlgo":      ALGO_FIRMA,
        "szSigner":    remitente.strip().lower(),
        "szSignerFp":  hashlib.sha256(publica_der).hexdigest(),
        "szSignature": base64.b64encode(firma).decode("ascii"),
    }, separators=(",", ":"))

    return (MARCA_FIRMA + "\n" + cabecera + "\n\n").encode("utf-8") + claro


# ---------------------------------------------------------------------------
#  The sealing.  THIS has to match clsEBlock.php and daeseal.js
# ---------------------------------------------------------------------------

def sellar(claro, pems):
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
    semilla  = clave_out + body_id

    enc_keys = {}
    for pem in pems:
        publica = serialization.load_pem_public_key(pem.encode("ascii"))
        der = publica.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        # RSA-OAEP with SHA-1: it is what OpenSSL uses by default and
        # therefore what is in all the mail already delivered. Changing
        # it here would leave the messages unreadable for the rest of
        # the system.
        sellada = publica.encrypt(semilla, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(), label=None))

        enc_keys[hashlib.sha256(der).hexdigest()] = \
            base64.b64encode(sellada).decode("ascii")

    n_block = len(cifrado)
    n_head  = min(MAX_HEAD, int(n_block * RATIO_HEAD))
    n_head  = max(1, min(n_head, n_block - 1))

    cabecera = {
        "szVersion":  VERSION,
        "szAlgo":     ALGO,
        "szIv":       base64.b64encode(iv).decode("ascii"),
        "szTag":      base64.b64encode(tag).decode("ascii"),
        "nBlockSize": n_block,
        "nHeadSize":  n_head,
        "arrEncKeys": enc_keys,
        # szChecksum is NOT here: it was the digest of the entire
        # ciphertext, and it is exactly the value that takes the mask
        # off. Publishing it in the piece that travels by mail would
        # reduce all of this to nothing.
        "szPayload":  base64.b64encode(cifrado[:n_head]).decode("ascii"),
    }

    return (json.dumps(cabecera, separators=(",", ":")),
            cifrado[n_head:],
            body_id.hex())


# ---------------------------------------------------------------------------
#  The delivery
# ---------------------------------------------------------------------------

def entregar(servidor, usuario, contrasena, para, cabecera, cuerpo, body_id, retencion):
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
                   help="tu clave privada en PEM, para firmar el mensaje")
    p.add_argument("--clave-contrasena", help="contrasenya de esa clave privada")
    p.add_argument("--clave-para", action="append", default=[], metavar="PEM",
                   help="clave publica del destinatario en un fichero, en vez "
                        "de pedirsela al directorio; repite la opcion para varios")
    p.add_argument("--copia", metavar="CLAVE_PUBLICA",
                   help="tu clave publica, para poder leer tu propia copia")
    p.add_argument("--retencion", choices=["permanent", "expiring", "ephemeral"],
                   help="cuanto vive la segunda pieza; por defecto, tu preferencia")
    p.add_argument("--servidor", default="https://doubleat.email")
    p.add_argument("--contrasena", help="la de tu buzon; si no, se pide al vuelo")
    p.add_argument("--solo-ficheros", metavar="PREFIJO",
                   help="no envia: deja PREFIJO.ehead y PREFIJO.ebody en disco")
    args = p.parse_args()

    texto = args.texto
    if args.texto_fichero:
        with open(args.texto_fichero, "r", encoding="utf-8") as f:
            texto = f.read()

    aviso("Montando el mensaje...")
    claro = montar_mime(args.de, args.para, args.asunto, texto, args.adjunto)

    if args.firmar:
        aviso("Firmando con tu clave privada...")
        claro = firmar(claro, args.firmar, args.de, args.clave_contrasena)
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
        pems = []
        for ruta in args.clave_para:
            with open(ruta, "r", encoding="ascii") as f:
                pems.append(f.read())
    else:
        aviso("Buscando las claves publicas:")
        pems = [clave_publica_de(args.servidor, d) for d in args.para]

    if args.copia:
        with open(args.copia, "r", encoding="ascii") as f:
            pems.append(f.read())
        aviso("  (incluida tu clave, para poder leer tu copia)")

    aviso("Cifrando en este ordenador...")
    cabecera, cuerpo, body_id = sellar(claro, pems)
    aviso("  eHead %d bytes,  eBody %d bytes" % (len(cabecera), len(cuerpo)))

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
                    cabecera, cuerpo, body_id, args.retencion)

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
