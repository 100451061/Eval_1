import os
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Usaremos el modo de operación AES-GCM para cifrar y autenticar los datos.
# AES- Galois/Counter Mode

# creamos la tabla clave-maestra
# creamos la tabla datos_protegidos

# Ruta a la base de datos
DB_PATH = "hospital.db"


# Generar clave para AES-GCM (32 bytes para AES-256)
def generar_clave():
    return os.urandom(32)


# Guardar clave en la base de datos
def almacenar_clave(clave):
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clave_maestra (
            id INTEGER PRIMARY KEY,
            clave BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT OR REPLACE INTO clave_maestra (id, clave) VALUES (1, ?)", (clave,))
    conexion.commit()
    conexion.close()


# Recuperar clave de la base de datos
def cargar_clave():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT clave FROM clave_maestra WHERE id = 1")
    row = cursor.fetchone()
    conexion.close()
    if row is None:
        raise ValueError("No se encontró una clave maestra.")
    return row[0]


# Cifrar datos con AES-GCM
def cifrar_datos(datos, clave):
    iv = os.urandom(12)  # Nonce de 12 bytes para GCM
    cifrador = Cipher(algorithms.AES(clave), modes.GCM(iv), backend=default_backend()).encryptor()
    texto_cifrado = cifrador.update(datos.encode()) + cifrador.finalize()
    return iv, texto_cifrado, cifrador.tag


# Almacenar datos cifrados en la base de datos
def almacenar_datos_cifrados(mensaje):
    clave = cargar_clave()
    iv, texto_cifrado, tag = cifrar_datos(mensaje, clave)

    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS datos_protegidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            iv BLOB NOT NULL,
            texto_cifrado BLOB NOT NULL,
            tag BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT INTO datos_protegidos (iv, texto_cifrado, tag) VALUES (?, ?, ?)", (iv, texto_cifrado, tag))
    conexion.commit()
    conexion.close()
    print("Mensaje cifrado y almacenado en la base de datos.")


# Descifrar datos con AES-GCM
def descifrar_datos(mensaje_id):
    clave = cargar_clave()
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT iv, texto_cifrado, tag FROM datos_protegidos WHERE id = ?", (mensaje_id,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        raise ValueError("No se encontró el mensaje cifrado con el ID proporcionado.")

    iv, texto_cifrado, tag = row
    descifrador = Cipher(algorithms.AES(clave), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    datos_descifrados = descifrador.update(texto_cifrado) + descifrador.finalize()
    print("Datos descifrados exitosamente.")
    return datos_descifrados.decode()
