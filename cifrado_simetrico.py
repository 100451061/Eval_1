from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def cifrar_datos(mensaje, clave):
    cipher = AES.new(clave, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(mensaje.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct


def descifrar_datos(iv, ct, clave):
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')
