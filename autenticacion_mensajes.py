# archivo: autenticacion_mensajes.py
import hashlib
import hmac


def generar_mac(mensaje, clave):
    mac = hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256).hexdigest()
    return mac


def verificar_mac(mensaje, mac, clave):
    mac_nuevo = hmac.new(clave, mensaje.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, mac_nuevo)
