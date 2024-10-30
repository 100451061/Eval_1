# Ventana hospital gregorio marañón
import sqlite3
import tkinter as tk
from tkinter import messagebox, Toplevel

from autenticacion_mensajes import almacenar_mensaje, verificar_mensaje
from cifrado_simetrico import almacenar_datos_cifrados, descifrar_datos
from usuario_autenticacion import registrar_usuario, autenticar_usuario

# Ruta de la base de datos
DB_PATH = "hospital.db"

# Crear la ventana principal para registrar y autenticar
root = tk.Tk()
root.title("Sistema de Seguridad del Hospital - Inicio de Sesión")
root.geometry("400x400")

# Variables para los campos de entrada
usuario_var = tk.StringVar()
contrasena_var = tk.StringVar()
mensaje_var = tk.StringVar()
mensaje_id_var = tk.StringVar()


# Funciones de autenticación
def registrar():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    try:
        registrar_usuario(usuario, contrasena)
        messagebox.showinfo("Registro", f"Usuario '{usuario}' registrado exitosamente.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def autenticar():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    resultado = autenticar_usuario(usuario, contrasena)
    if resultado == "Autenticación exitosa":
        messagebox.showinfo("Autenticación", resultado)
        abrir_ventana_mensajes()  # Abre la segunda ventana
    else:
        messagebox.showwarning("Autenticación", resultado)


# Crear la segunda ventana para el manejo de mensajes
def abrir_ventana_mensajes():
    ventana_mensajes = Toplevel(root)
    ventana_mensajes.title("Sistema de Seguridad del Hospital - Cifrado de Mensajes")
    ventana_mensajes.geometry("400x600")

    # Elementos de la segunda ventana
    tk.Label(ventana_mensajes, text="Mensaje para cifrar/autenticar").pack()
    tk.Entry(ventana_mensajes, textvariable=mensaje_var).pack()

    tk.Button(ventana_mensajes, text="Cifrar Mensaje", command=cifrar_mensaje).pack()

    tk.Label(ventana_mensajes, text="ID del mensaje para descifrar/verificar").pack()
    tk.Entry(ventana_mensajes, textvariable=mensaje_id_var).pack()

    tk.Button(ventana_mensajes, text="Descifrar Mensaje", command=descifrar_mensaje).pack()
    tk.Button(ventana_mensajes, text="Autenticar Mensaje (HMAC)", command=autenticar_mensaje).pack()
    tk.Button(ventana_mensajes, text="Verificar Autenticidad", command=verificar_autenticidad).pack()

    # Botones para limpiar las tablas de la base de datos
    tk.Button(ventana_mensajes, text="Limpiar Usuarios", command=limpiar_usuarios).pack()
    tk.Button(ventana_mensajes, text="Limpiar Mensajes Cifrados", command=limpiar_mensajes_cifrados).pack()
    tk.Button(ventana_mensajes, text="Limpiar Mensajes Autenticados", command=limpiar_mensajes_autenticados).pack()

    # Botón de "Salir" en la segunda ventana
    tk.Button(ventana_mensajes, text="Salir", command=root.quit).pack()


# Funciones de la GUI para el manejo de mensajes
def cifrar_mensaje():
    mensaje = mensaje_var.get()
    try:
        almacenar_datos_cifrados(mensaje)
        messagebox.showinfo("Cifrado", "Mensaje cifrado y almacenado correctamente.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def descifrar_mensaje():
    mensaje_id = mensaje_id_var.get()
    try:
        mensaje = descifrar_datos(int(mensaje_id))
        messagebox.showinfo("Descifrado", f"Mensaje descifrado: {mensaje}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def autenticar_mensaje():
    mensaje = mensaje_var.get()
    try:
        almacenar_mensaje(mensaje)
        messagebox.showinfo("HMAC", "Mensaje autenticado y almacenado correctamente.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def verificar_autenticidad():
    mensaje_id = mensaje_id_var.get()
    mensaje = mensaje_var.get()
    try:
        if verificar_mensaje(int(mensaje_id), mensaje):
            messagebox.showinfo("Verificación", "El mensaje es auténtico.")
        else:
            messagebox.showwarning("Verificación", "El mensaje no es auténtico.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Funciones para limpiar las tablas en la base de datos
def limpiar_usuarios():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM usuarios")
    conexion.commit()
    conexion.close()
    messagebox.showinfo("Limpiar Usuarios", "Todos los usuarios han sido eliminados.")


def limpiar_mensajes_cifrados():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM datos_protegidos")
    conexion.commit()
    conexion.close()
    messagebox.showinfo("Limpiar Mensajes Cifrados", "Todos los mensajes cifrados han sido eliminados.")


def limpiar_mensajes_autenticados():
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM mensajes_autenticados")
    conexion.commit()
    conexion.close()
    messagebox.showinfo("Limpiar Mensajes Autenticados", "Todos los mensajes autenticados han sido eliminados.")


# Elementos de la ventana principal para registro y autenticación
tk.Label(root, text="Usuario").pack()
tk.Entry(root, textvariable=usuario_var).pack()

tk.Label(root, text="Contraseña").pack()
tk.Entry(root, textvariable=contrasena_var, show="*").pack()

tk.Button(root, text="Registrar", command=registrar).pack()
tk.Button(root, text="Autenticar", command=autenticar).pack()

# Botón de "Salir" en la ventana principal
tk.Button(root, text="Salir", command=root.quit).pack()

# Iniciar la aplicación
root.mainloop()
