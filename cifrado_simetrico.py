# cifrado_simetrico.py
import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def cifrar_datos(mensaje, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    texto_cifrado = encryptor.update(mensaje.encode()) + encryptor.finalize()
    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(texto_cifrado).decode('utf-8'), base64.b64encode(encryptor.tag).decode(
        'utf-8')


def descifrar_datos(iv, texto_cifrado, tag, key):
    iv = base64.b64decode(iv)
    texto_cifrado = base64.b64decode(texto_cifrado)
    tag = base64.b64decode(tag)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    mensaje_descifrado = decryptor.update(texto_cifrado) + decryptor.finalize()
    return mensaje_descifrado.decode('utf-8')
