import base64
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Clave de cifrado simétrico
clave_simetrica = get_random_bytes(16)  # Puedes ajustar la longitud de la clave según el algoritmo


def guardar_cifrado_en_json(iv, ct):
    """Función para guardar el IV y el texto cifrado en un archivo JSON."""
    try:
        # Carga los datos existentes si el archivo ya existe
        try:
            with open("mensajes_cifrados.json", "r") as file:
                cifrados = json.load(file)
        except FileNotFoundError:
            cifrados = []

        # Agrega el nuevo cifrado al listado
        cifrado = {"IV": iv, "Texto Cifrado": ct}
        cifrados.append(cifrado)

        # Guarda los datos actualizados en el archivo
        with open("mensajes_cifrados.json", "w") as file:
            json.dump(cifrados, file, indent=4)

        print("IV y Texto Cifrado guardados en mensajes_cifrados.json.")
    except Exception as e:
        print(f"Error al intentar escribir en mensajes_cifrados.json: {e}")


def cifrar_datos(mensaje, clave):
    """Cifra un mensaje utilizando AES en modo CBC y retorna el IV y el texto cifrado en base64."""
    cipher = AES.new(clave, AES.MODE_CBC)
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    # Padding del mensaje
    mensaje_bytes = mensaje.encode('utf-8')
    padding_length = 16 - (len(mensaje_bytes) % 16)
    mensaje_bytes += bytes([padding_length]) * padding_length
    ct_bytes = cipher.encrypt(mensaje_bytes)
    ct = base64.b64encode(ct_bytes).decode('utf-8')

    # Guardar IV y texto cifrado en JSON
    guardar_cifrado_en_json(iv, ct)

    return iv, ct


def descifrar_datos(iv, ct, clave):
    """Descifra un texto cifrado utilizando AES en modo CBC y retorna el mensaje original."""
    iv_bytes = base64.b64decode(iv)
    ct_bytes = base64.b64decode(ct)
    cipher = AES.new(clave, AES.MODE_CBC, iv=iv_bytes)
    mensaje_bytes = cipher.decrypt(ct_bytes)
    # Eliminar padding
    padding_length = mensaje_bytes[-1]
    mensaje_bytes = mensaje_bytes[:-padding_length]
    return mensaje_bytes.decode('utf-8')
