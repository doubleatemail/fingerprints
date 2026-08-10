#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dae_send.py - Enviar un correo puzzle SIN pasar por nuestro navegador

Dominio publico. Copialo, leelo entero, cambialo, redistribuyelo.

------------------------------------------------------
PARA QUE SIRVE
------------------------------------------------------
Cuando escribes desde la web, el programa que cifra tu correo te lo
manda nuestro servidor cada vez que abres la pagina. Un servidor
comprometido, o presionado, podria mandarte una version que se guarde una
copia de lo que escribes, y no lo notarias. Eso vale aqui y vale para
cualquier correo cifrado que funcione dentro de un navegador.

Este programa es la salida. Cifra en TU ordenador, con codigo que puedes
leer entero antes de ejecutarlo, y al servidor solo le llegan las dos
piezas ya cerradas. No ve tu mensaje, ni tus adjuntos, ni puede verlos
despues.

Su pareja es dae_open.py, que hace lo mismo al reves.

------------------------------------------------------
COMO SE USA
------------------------------------------------------
    python dae_send.py --de ana@doubleat.email \\
                       --para luis@doubleat.email \\
                       --asunto "Hola" \\
                       --texto "Nos vemos el martes." \\
                       --adjunto contrato.pdf \\
                       --firmar mi_clave_privada.pem

Te pedira la contrasenya de tu buzon, que es la misma del correo. No se
guarda en ninguna parte.

Con --solo-ficheros no envia nada: deja el .ehead y el .ebody en disco
para que los mires antes de decidir.

------------------------------------------------------
QUE HACE POR DENTRO, EN ORDEN
------------------------------------------------------
 1. Monta tu mensaje en MIME, adjuntos incluidos.
 2. Lo firma, si le das tu clave privada. La firma va DENTRO de lo que se
    cifra: fuera anunciaria a quien intercepte quien escribe.
 3. Busca la clave publica de cada destinatario en el directorio.
 4. Cifra todo con AES-256-GCM, con una clave nueva para este mensaje.
 5. TRANSFORMACION TODO-O-NADA: enmascara esa clave con el resumen del
    cifrado ENTERO. Sin las dos piezas completas no se recupera, asi que a
    quien intercepte una no le sirve de nada, ni con el tiempo, ni con la
    clave privada del destinatario.
 6. Parte el resultado: el 10 % va en el eHead y el resto en el eBody.
 7. Entrega las dos piezas. El servidor reparte sin abrir nada.

Los pasos 4, 5 y 6 tienen que dar EXACTAMENTE lo mismo que clsEBlock.php
y que daeseal.js. Hay prueba cruzada en tests/testCruzado.php: si las
tres no coinciden byte a byte, hay correo que se abre en un sitio y no en
otro. Si cambias algo aqui, pasa esa prueba.
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

# Alfabeto z-base32, el que usa el directorio de claves. No es el base32
# de siempre: esta ordenado para que los caracteres que se confunden al
# leerlos en voz alta caigan lejos unos de otros.
ALFABETO_Z = "ybndrfg8ejkmcpqxot1uwisza345h769"


def aviso(texto):
    print(texto, file=sys.stderr)


# ---------------------------------------------------------------------------
#  El directorio de claves
# ---------------------------------------------------------------------------

def zbase32(datos):
    bits = "".join(format(b, "08b") for b in datos)
    salida = ""
    for i in range(0, len(bits), 5):
        trozo = bits[i:i + 5].ljust(5, "0")
        salida += ALFABETO_Z[int(trozo, 2)]
    return salida


def hu(direccion):
    """El identificador de una direccion en el directorio.

    Solo la parte local, en minusculas. No se pregunta por la direccion
    sino por su resumen, para que el directorio no se pueda recorrer y
    nadie pueda cosechar la lista de usuarios probando nombres.
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

    # La huella se ensenya SIEMPRE. Quien sirve el directorio podria colar
    # su propia clave, y contra eso no protege el cifrado: lo unico que
    # protege es que la compares con tu destinatario por otro canal.
    if huella:
        aviso("  %s -> %s" % (direccion, " ".join(
            huella.upper()[i:i + 4] for i in range(0, len(huella), 4))))
    return pem


# ---------------------------------------------------------------------------
#  El mensaje
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
    """Envuelve el mensaje con su firma, ANTES de cifrarlo.

    La firma tiene que quedar dentro del cifrado: fuera le diria a quien
    intercepte el correo quien lo escribe, que es justo lo que el
    protocolo evita.
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
#  El sellado.  ESTO tiene que coincidir con clsEBlock.php y daeseal.js
# ---------------------------------------------------------------------------

def sellar(claro, pems):
    clave = secrets.token_bytes(32)
    iv    = secrets.token_bytes(12)

    # AESGCM devuelve el tag pegado al final; el resto del sistema los
    # lleva separados, asi que se parten aqui.
    con_tag  = AESGCM(clave).encrypt(iv, claro, None)
    cifrado  = con_tag[:-16]
    tag      = con_tag[-16:]

    # TRANSFORMACION TODO-O-NADA. La clave no viaja: viaja enmascarada
    # con el resumen del cifrado ENTERO. Para quitarle la mascara hacen
    # falta las dos piezas hasta el ultimo byte, asi que a quien
    # intercepte una no le sirve de nada. No es que le falte potencia de
    # calculo: le faltan datos, y los datos que no existen no se calculan.
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

        # RSA-OAEP con SHA-1: es lo que usa OpenSSL por defecto y por
        # tanto lo que hay en todo el correo ya repartido. Cambiarlo aqui
        # dejaria los mensajes ilegibles para el resto del sistema.
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
        # szChecksum NO va: era el resumen del cifrado entero, y es
        # exactamente el valor que quita la mascara. Publicarlo en la
        # pieza que viaja por correo dejaria todo esto en nada.
        "szPayload":  base64.b64encode(cifrado[:n_head]).decode("ascii"),
    }

    return (json.dumps(cabecera, separators=(",", ":")),
            cifrado[n_head:],
            body_id.hex())


# ---------------------------------------------------------------------------
#  La entrega
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

    # Si te dan las claves a mano, no se consulta el directorio. Quien
    # ya tiene la clave de su destinatario, comprobada por otro canal, no
    # tiene por que fiarse de que se la sirvamos nosotros: el directorio
    # es un punto de confianza y esta es la forma de esquivarlo.
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
