import hmac
import hashlib
from base64 import b64encode, b64decode


def generar_mac(mensaje, clave):
    mac = hmac.new(clave, mensaje.encode(), hashlib.sha256)
    return b64encode(mac.digest()).decode()


def verificar_mac(mensaje, mac_recibido, clave):
    mac_calculado = generar_mac(mensaje, clave)
    return hmac.compare_digest(mac_calculado, mac_recibido)
