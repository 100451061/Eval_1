import os
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Ruta de la base de datos SQLite
DB_PATH = "hospital.db"


# Inicializar la base de datos y crear la tabla de usuarios si no existe
def inicializar_bd():
    """
    Inicializa la base de datos hospital.db y crea la tabla 'usuarios' si no existe.
    La tabla 'usuarios' tiene tres columnas:
    - usuario: Texto que actúa como clave primaria.
    - salt: Salt utilizado para derivar la clave.
    - pwd_hash: Hash de la contraseña derivado con Scrypt.
    """
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


# Función para generar el hash de la contraseña usando Scrypt
def generar_pwd_hash(contrasena, salt):
    """
    Genera un hash seguro de la contraseña usando Scrypt y un salt único.
    Argumentos:
        contrasena (str): La contraseña en texto plano.
        salt (bytes): Un valor aleatorio único.
    Retorna:
        bytes: El hash de la contraseña.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(contrasena.encode())


# Función para registrar un nuevo usuario
def registrar_usuario(usuario, contrasena):
    """
    Registra un nuevo usuario en la base de datos con una contraseña hasheada.
    Argumentos:
        usuario (str): Nombre de usuario.
        contrasena (str): Contraseña en texto claro.
    """
    salt = os.urandom(16)  # Genera un salt único de 16 bytes
    pwd_hash = generar_pwd_hash(contrasena, salt)  # Genera el hash de la contraseña

    # Guardar el usuario, salt y hash en la base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO usuarios (usuario, salt, pwd_hash) VALUES (?, ?, ?)",
                   (usuario, salt, pwd_hash))
    conexion.commit()
    conexion.close()
    print(f"Usuario '{usuario}' registrado exitosamente.")


# Función para autenticar un usuario
def autenticar_usuario(usuario, contrasena):
    """
    Autentica a un usuario verificando que la contraseña ingresada coincida con el hash almacenado.
    Argumentos:
        usuario (str): Nombre de usuario.
        contrasena (str): Contraseña en texto claro.
    Retorna:
        str: Mensaje indicando si la autenticación fue exitosa o si hubo un error.
    """
    # Recuperar el salt y hash de la base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT salt, pwd_hash FROM usuarios WHERE usuario = ?", (usuario,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        return "Usuario no encontrado"

    salt, stored_pwd_hash = row

    # Intentar derivar el hash con la contraseña ingresada
    try:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=default_backend()
        )
        kdf.verify(contrasena.encode(), stored_pwd_hash)  # Verifica que el hash coincide
        return "Autenticación exitosa"
    except Exception:
        return "Contraseña incorrecta"


# Función para generar un HMAC
def generar_hmac(mensaje, clave):
    """
    Genera un código HMAC para verificar la integridad de un mensaje.
    Argumentos:
        mensaje (bytes): Mensaje que queremos proteger.
        clave (bytes): Clave secreta para el HMAC.
    Retorna:
        bytes: El código HMAC.
    """
    h = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)
    return h.finalize()


# Inicializar la base de datos
inicializar_bd()
