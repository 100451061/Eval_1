import logging
import os
import re
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DB_PATH = "hospital.db"
# mejora añadida
# Configuración del logger
logging.basicConfig(filename="hospital_security.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def validar_datos_usuario(usuario, contrasena):
    if not re.match("^[A-Za-z0-9]+$", usuario):
        raise ValueError("El nombre de usuario debe contener solo letras y números.")
    if len(contrasena) < 8 or not re.search("[A-Za-z]", contrasena) or not re.search("[0-9]", contrasena):
        raise ValueError("La contraseña debe tener al menos 8 caracteres y contener letras y números.")


def inicializar_bd():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            usuario TEXT PRIMARY KEY,
            salt BLOB NOT NULL,
            pwd_hash BLOB NOT NULL
        )
    ''')
    conexion.commit()
    conexion.close()


def generar_pwd_hash(contrasena, salt):
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
    return kdf.derive(contrasena.encode())


def registrar_usuario(usuario, contrasena):
    validar_datos_usuario(usuario, contrasena)
    salt = os.urandom(16)
    pwd_hash = generar_pwd_hash(contrasena, salt)
    try:
        conexion = sqlite3.connect(DB_PATH)
        cursor = conexion.cursor()
        cursor.execute("INSERT INTO usuarios (usuario, salt, pwd_hash) VALUES (?, ?, ?)", (usuario, salt, pwd_hash))
        conexion.commit()
        logging.info(f"Usuario '{usuario}' registrado.")
    except Exception as e:
        logging.error(f"Error al registrar usuario '{usuario}': {e}")
        raise
    finally:
        conexion.close()


def autenticar_usuario(usuario, contrasena):
    validar_datos_usuario(usuario, contrasena)
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT salt, pwd_hash FROM usuarios WHERE usuario = ?", (usuario,))
    row = cursor.fetchone()
    conexion.close()
    if row is None:
        raise ValueError("Usuario no encontrado")
    salt, stored_pwd_hash = row
    try:
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
        kdf.verify(contrasena.encode(), stored_pwd_hash)
        logging.info(f"Usuario '{usuario}' autenticado.")
        return True
    except Exception as e:
        logging.warning(f"Autenticación fallida para '{usuario}': {e}")
        return False
