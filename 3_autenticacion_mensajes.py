import hmac
import os
import sqlite3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# La autenticación de mensajes se asegura de que un mensaje recibido es auténtico y no ha sido modificado en el camino. Esto se logra
# generando un Código de Autenticación de Mensajes (MAC)

# El MAC se deriva del mensaje y una clave secreta compartida entre el emisor y el receptor. Solo alguien con la clave secreta puede
# crear y verificar este código, lo que da confianza en la fuente del mensaje y su contenido.


# la opción más recomendada es MAC Basados en Funciones Hash (HMAC) basado en SHA-256 (en comparación a MAC Basados en Cifrado de Bloques:)

# Seguro: SHA-256 proporciona una fuerte resistencia contra ataques, y HMAC es robusto contra ataques de colisión.

# Fácil de implementar:  HMAC es ampliamente soportado en bibliotecas de Python y es eficiente en términos de rendimiento.

# Ampliamente adoptado: HMAC se utiliza en muchos sistemas y protocolos, como TLS y APIs web, por su seguridad y eficiencia.


# Ruta a la base de datos
DB_PATH = "hospital.db"


# Generar clave secreta para HMAC
def generar_clave_hmac():
    return os.urandom(32)  # Clave de 256 bits


# Almacenar la clave HMAC en la base de datos
def almacenar_clave_hmac(clave_hmac):
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clave_hmac (
            id INTEGER PRIMARY KEY,
            clave BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT OR REPLACE INTO clave_hmac (id, clave) VALUES (1, ?)", (clave_hmac,))
    conexion.commit()
    conexion.close()


# Cargar la clave HMAC desde la base de datos
def cargar_clave_hmac():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT clave FROM clave_hmac WHERE id = 1")
    row = cursor.fetchone()
    conexion.close()
    if row is None:
        raise ValueError("No se encontró una clave HMAC.")
    return row[0]


# Generar HMAC para un mensaje
def generar_hmac(mensaje):
    clave_hmac = cargar_clave_hmac()
    h = hmac.HMAC(clave_hmac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje.encode())
    return h.finalize()


# Almacenar mensaje y su HMAC en la base de datos
def almacenar_mensaje(mensaje):
    mac = generar_hmac(mensaje)
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mensajes_autenticados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mensaje TEXT NOT NULL,
            mac BLOB NOT NULL
        )
    ''')
    cursor.execute("INSERT INTO mensajes_autenticados (mensaje, hmac) VALUES (?, ?)", (mensaje, mac))
    conexion.commit()
    conexion.close()
    print("Mensaje autenticado y almacenado en la base de datos.")


# Verificar la autenticidad de un mensaje
def verificar_mensaje(mensaje_id, mensaje):
    clave_hmac = cargar_clave_hmac()
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT hmac FROM mensajes_autenticados WHERE id = ?", (mensaje_id,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        raise ValueError("No se encontró el mensaje en la base de datos.")

    mac_almacenado = row[0]

    # Verificar el HMAC
    h = hmac.HMAC(clave_hmac, hashes.SHA256(), backend=default_backend())
    h.update(mensaje.encode())
    try:
        h.verify(mac_almacenado)
        print("El mensaje es auténtico.")
        return True
    except Exception:
        print("El mensaje no es auténtico.")
        return False
