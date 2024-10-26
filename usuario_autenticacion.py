import json

import bcrypt


def leer_usuarios():
    try:
        with open("usuarios.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def guardar_usuario(nombre_usuario, contraseña):
    usuarios = leer_usuarios()
    hashed = bcrypt.hashpw(contraseña.encode('utf-8'), bcrypt.gensalt())
    usuarios[nombre_usuario] = hashed.decode('utf-8')
    with open("usuarios.json", "w") as file:
        json.dump(usuarios, file)


def autenticar_usuario(nombre_usuario, contraseña):
    usuarios = leer_usuarios()
    hashed = usuarios.get(nombre_usuario)
    if not hashed:
        return "Usuario no encontrado"
    if bcrypt.checkpw(contraseña.encode('utf-8'), hashed.encode('utf-8')):
        return "Autenticación exitosa"
    else:
        return "Contraseña incorrecta"


def borrar_usuario(nombre_usuario):
    usuarios = leer_usuarios()
    if nombre_usuario in usuarios:
        del usuarios[nombre_usuario]
        with open("usuarios.json", "w") as file:
            json.dump(usuarios, file)
        return f"Usuario '{nombre_usuario}' eliminado exitosamente."
    else:
        return f"Usuario '{nombre_usuario}' no encontrado."
