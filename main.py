# archivo: main.py
from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac
from cifrado_simetrico import cifrar_datos, descifrar_datos
from usuario_autenticacion import guardar_usuario, autenticar_usuario

# Datos de prueba
clave_simetrica = get_random_bytes(16)  # AES-128 usa una clave de 16 bytes

# Autenticación de usuario
guardar_usuario("usuario1", "mi_contraseña_secreta")
print(autenticar_usuario("usuario1", "mi_contraseña_secreta"))

# Cifrado y descifrado de datos
mensaje = "Mensaje confidencial"
iv, ct = cifrar_datos(mensaje, clave_simetrica)
print("Cifrado:", iv, ct)
print("Descifrado:", descifrar_datos(iv, ct, clave_simetrica))

# Generación y verificación de MAC
mac = generar_mac(mensaje, clave_simetrica)
print("MAC:", mac)
print("MAC válido:", verificar_mac(mensaje, mac, clave_simetrica))
