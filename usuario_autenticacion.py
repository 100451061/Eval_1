# usuario_autenticacion.py
import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Función para derivar la clave
def derivar_clave(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


# Modificación de la función de registro para almacenar clave derivada y salt
def guardar_usuario(usuario, password):
    key, salt = derivar_clave(password)
    with open("usuarios.json", "r+") as file:
        usuarios = json.load(file)
        usuarios[usuario] = {
            "key": key.decode('utf-8'),  # Almacena la clave derivada
            "salt": base64.b64encode(salt).decode('utf-8')  # Guarda el salt como texto
        }
        file.seek(0)
        json.dump(usuarios, file, indent=4)


# Modificación de la función de autenticación para comparar claves derivadas
def autenticar_usuario(usuario, password):
    with open("usuarios.json", "r") as file:
        usuarios = json.load(file)
    if usuario in usuarios:
        salt = base64.b64decode(usuarios[usuario]["salt"])
        stored_key = usuarios[usuario]["key"].encode('utf-8')
        derived_key, _ = derivar_clave(password, salt)
        if derived_key == stored_key:
            return "Autenticación exitosa"
    return "Autenticación fallida"
