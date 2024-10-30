import sqlite3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Usaremos el modo de operación AES-GCM para cifrar y autenticar los datos.
# AES- Galois/Counter Mode

# Ruta de la base de datos  donde se almacenará la clave maestra y los datos cifrados
DB_PATH = "hospital.db"


# Función para inicializar la base de datos y crear tablas si no existen
def inicializar_bd():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()

    # Tabla para la clave maestra (solo un registro)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clave_maestra (
            id INTEGER PRIMARY KEY,
            clave BLOB NOT NULL
        )
    ''')

    # Tabla para almacenar datos cifrados
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mensajes_cifrados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL,
            texto_cifrado BLOB NOT NULL
        )
    ''')

    conexion.commit()
    conexion.close()


# Generar y almacenar la clave maestra en la base de datos
def generar_clave():
    clave = get_random_bytes(32)  # Clave de 256 bits para AES-GCM
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()

    # Insertar la clave en la base de datos
    cursor.execute("INSERT OR REPLACE INTO clave_maestra (id, clave) VALUES (1, ?)", (clave,))

    conexion.commit()
    conexion.close()
    print("Clave maestra generada y almacenada en la base de datos.")


# Cargar la clave maestra desde la base de datos
def cargar_clave():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()

    # Obtener la clave desde la base de datos
    cursor.execute("SELECT clave FROM clave_maestra WHERE id = 1")
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        raise ValueError("No se ha encontrado una clave maestra. Ejecute 'generar_clave()' primero.")

    return row[0]


# Cifrar datos usando AES-GCM y almacenar en la base de datos
def cifrar_datos(datos):
    clave = cargar_clave()  # Cargar la clave maestra
    iv = get_random_bytes(12)  # Nonce de 12 bytes para GCM

    # Crear el cifrador AES-GCM
    cifrador = AES.new(clave, AES.MODE_GCM, nonce=iv)
    texto_cifrado, tag = cifrador.encrypt_and_digest(datos.encode())

    # Guardar el nonce, tag y texto cifrado en la base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO mensajes_cifrados (nonce, tag, texto_cifrado) VALUES (?, ?, ?)", (iv, tag, texto_cifrado))

    conexion.commit()
    conexion.close()
    print("Datos cifrados y almacenados en la base de datos.")


# Descifrar datos usando AES-GCM desde la base de datos
def descifrar_datos(mensaje_id):
    clave = cargar_clave()  # Cargar la clave maestra

    # Obtener el mensaje cifrado por su ID
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT nonce, tag, texto_cifrado FROM mensajes_cifrados WHERE id = ?", (mensaje_id,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        raise ValueError("No se ha encontrado el mensaje cifrado con el ID proporcionado.")

    nonce, tag, texto_cifrado = row

    # Crear el cifrador AES-GCM para descifrar
    cifrador = AES.new(clave, AES.MODE_GCM, nonce=nonce)
    datos_descifrados = cifrador.decrypt_and_verify(texto_cifrado, tag)

    print("Datos descifrados exitosamente.")
    return datos_descifrados.decode()
