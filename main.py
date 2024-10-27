from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac
from cifrado_simetrico import cifrar_datos, descifrar_datos
from usuario_autenticacion import guardar_usuario, autenticar_usuario

# Generar clave simétrica de prueba
clave_simetrica = get_random_bytes(16)

# Prueba de registro y autenticación de usuario
guardar_usuario("enfermero1", "contraseña_segura123")
print(autenticar_usuario("enfermero1", "contraseña_segura123"))

# Prueba de cifrado y descifrado
mensaje = "Información confidencial del paciente"
iv, ct = cifrar_datos(mensaje, clave_simetrica)
print("Mensaje cifrado:", iv, ct)
print("Mensaje descifrado:", descifrar_datos(iv, ct, clave_simetrica))

# Prueba de generación y verificación de MAC
mac = generar_mac(mensaje, clave_simetrica)
print("MAC:", mac)
print("MAC válido:", verificar_mac(mensaje, mac, clave_simetrica))
