import hashlib
import hmac
from base64 import b64encode


# Generar una MAC usando HMAC-SHA256
def generar_mac(mensaje, clave):
    mac = hmac.new(clave, mensaje.encode(), hashlib.sha256)
    return b64encode(mac.digest()).decode()


# Verificar una MAC comparándola con la recibida
def verificar_mac(mensaje, mac_recibido, clave):
    mac_calculado = generar_mac(mensaje, clave)
    return hmac.compare_digest(mac_calculado, mac_recibido)
