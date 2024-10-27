import sqlite3
from tkinter import messagebox

import bcrypt

DB_PATH = "hospital.db"


# Leer usuarios desde la base de datos
def leer_usuarios():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT usuario, contraseña FROM usuarios")
    usuarios = {row[0]: row[1] for row in cursor.fetchall()}
    conexion.close()
    return usuarios


# Guardar usuario con contraseña encriptada usando bcrypt
def guardar_usuario(usuario, contraseña):
    if usuario in leer_usuarios():
        messagebox.showerror("Error", "El usuario ya existe.")
        return
    hashed = bcrypt.hashpw(contraseña.encode(), bcrypt.gensalt()).decode()
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO usuarios (usuario, contraseña) VALUES (?, ?)", (usuario, hashed))
    conexion.commit()
    conexion.close()


# Autenticar usuario verificando su contraseña
def autenticar_usuario(usuario, contraseña):
    usuarios = leer_usuarios()
    if usuario in usuarios and bcrypt.checkpw(contraseña.encode(), usuarios[usuario].encode()):
        return "Autenticación exitosa"
    return "Usuario o contraseña incorrecta"


# Borrar usuario de la base de datos
def borrar_usuario(usuario):
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))
    conexion.commit()
    conexion.close()
    return "Usuario eliminado exitosamente" if cursor.rowcount > 0 else "Usuario no encontrado"
