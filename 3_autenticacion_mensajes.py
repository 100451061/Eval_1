import hashlib
import hmac
import sqlite3

# La autenticación de mensajes se asegura de que un mensaje recibido es auténtico y no ha sido modificado en el camino. Esto se logra
# generando un Código de Autenticación de Mensajes (MAC)

# El MAC se deriva del mensaje y una clave secreta compartida entre el emisor y el receptor. Solo alguien con la clave secreta puede
# crear y verificar este código, lo que da confianza en la fuente del mensaje y su contenido.


# la opción más recomendada es MAC Basados en Funciones Hash (HMAC) basado en SHA-256 (en comparación a MAC Basados en Cifrado de Bloques:)

# Seguro: SHA-256 proporciona una fuerte resistencia contra ataques, y HMAC es robusto contra ataques de colisión.

# Fácil de implementar:  HMAC es ampliamente soportado en bibliotecas de Python y es eficiente en términos de rendimiento.

# Ampliamente adoptado: HMAC se utiliza en muchos sistemas y protocolos, como TLS y APIs web, por su seguridad y eficiencia.


# Ruta de la base de datos
DB_PATH = "hospital.db"


# Inicializar la base de datos y crear la tabla de autenticación de mensajes si no existe
def inicializar_bd():
    """
    Inicializa la base de datos y crea la tabla de mensajes autenticados si no existe.
    """
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS autenticacion_mensajes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mensaje TEXT NOT NULL,
            mac BLOB NOT NULL
        )
    ''')
    conexion.commit()
    conexion.close()


# Generar un HMAC para un mensaje dado
def generar_hmac(mensaje, clave_secreta):
    """
    Genera un HMAC del mensaje usando la clave secreta y SHA-256.
    Argumentos:
        mensaje (str): El mensaje a autenticar.
        clave_secreta (bytes): La clave secreta compartida para el HMAC.
    Retorna:
        bytes: El código HMAC generado.
    """
    hmac_obj = hmac.new(clave_secreta, mensaje.encode(), hashlib.sha256)
    return hmac_obj.digest()


# Guardar un mensaje y su MAC en la base de datos
def guardar_mensaje_autenticado(mensaje, clave_secreta):
    """
    Cifra el mensaje con HMAC-SHA256 y lo guarda en la base de datos.
    Argumentos:
        mensaje (str): El mensaje a autenticar.
        clave_secreta (bytes): La clave secreta compartida.
    """
    mac = generar_hmac(mensaje, clave_secreta)

    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO autenticacion_mensajes (mensaje, mac) VALUES (?, ?)", (mensaje, mac))

    conexion.commit()
    conexion.close()
    print("Mensaje autenticado y guardado en la base de datos.")


# Verificar la autenticidad de un mensaje
def verificar_mensaje(mensaje_id, mensaje, clave_secreta):
    """
    Verifica la autenticidad del mensaje comparando el MAC almacenado con uno recalculado.
    Argumentos:
        mensaje_id (int): ID del mensaje en la base de datos.
        mensaje (str): El mensaje a verificar.
        clave_secreta (bytes): La clave secreta compartida.
    Retorna:
        bool: True si el mensaje es auténtico, False en caso contrario.
    """
    mac_actual = generar_hmac(mensaje, clave_secreta)

    # Recuperar el MAC original desde la base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT mac FROM autenticacion_mensajes WHERE id = ?", (mensaje_id,))
    row = cursor.fetchone()
    conexion.close()

    if row is None:
        print("No se encontró el mensaje en la base de datos.")
        return False

    mac_almacenado = row[0]

    # Comparar ambos MAC de forma segura
    if hmac.compare_digest(mac_actual, mac_almacenado):
        print("El mensaje es auténtico.")
        return True
    else:
        print("El mensaje no es auténtico.")
        return False
