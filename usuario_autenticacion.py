import json
from tkinter import messagebox

import bcrypt

RUTA_USUARIOS = "usuarios.json"


def leer_usuarios():
    try:
        with open(RUTA_USUARIOS, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def guardar_usuario(usuario, contraseña):
    usuarios = leer_usuarios()
    if usuario in usuarios:
        messagebox.showerror("Error", "El usuario ya existe.")
        return

    hashed = bcrypt.hashpw(contraseña.encode(), bcrypt.gensalt())
    usuarios[usuario] = hashed.decode()

    with open(RUTA_USUARIOS, 'w') as file:
        json.dump(usuarios, file, indent=4)


def autenticar_usuario(usuario, contraseña):
    usuarios = leer_usuarios()
    if usuario in usuarios and bcrypt.checkpw(contraseña.encode(), usuarios[usuario].encode()):
        return "Autenticación exitosa"
    return "Usuario o contraseña incorrecta"


def borrar_usuario(usuario):
    usuarios = leer_usuarios()
    if usuario in usuarios:
        del usuarios[usuario]
        with open(RUTA_USUARIOS, 'w') as file:
            json.dump(usuarios, file, indent=4)
        return "Usuario eliminado exitosamente"
    return "Usuario no encontrado"
