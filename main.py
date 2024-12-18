import re  # Asegúrate de importar re para las expresiones regulares
import sqlite3
import tkinter as tk
from tkinter import messagebox, Toplevel

from autenticacion_mensajes import almacenar_mensaje, verificar_mensaje
from cifrado_simetrico import almacenar_datos_cifrados, descifrar_datos
from usuario_autenticacion import registrar_usuario, autenticar_usuario


# Mejora extra :) nos aseguramos de tener al menos 8 caracteres y contener letras y números
def validar_datos_usuario(usuario, contrasena):
    if not re.match("^[A-Za-z0-9]+$", usuario):
        raise ValueError("El nombre de usuario debe contener solo letras y números.")
    if len(contrasena) < 8 or not re.search("[A-Za-z]", contrasena) or not re.search("[0-9]", contrasena):
        raise ValueError("La contraseña debe tener al menos 8 caracteres y contener letras y números.")


# Ruta de la base de datos
DB_PATH = "hospital.db"

# Configuración de la ventana principal de la aplicación
root = tk.Tk()
root.title("Sistema de Seguridad del Hospital - Inicio de Sesión")
root.geometry("400x400")
root.configure(bg="#f0f4f8")

# Variables para almacenar entradas de usuario
usuario_var = tk.StringVar()
contrasena_var = tk.StringVar()
mensaje_var = tk.StringVar()
mensaje_id_var = tk.StringVar()

# Título principal de la interfaz gráfica
titulo_label = tk.Label(root, text="Hospital Gregorio Marañón \n Sec Hosp", font=("Arial", 16, "bold"), bg="#f0f4f8", fg="#333")
titulo_label.pack(pady=(10, 20))


# Función para registrar usuarios en la base de datos
def registrar():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    try:
        # Validamos los datos del usuario antes de registrarlo
        validar_datos_usuario(usuario, contrasena)
        registrar_usuario(usuario, contrasena)
        messagebox.showinfo("Registro", f"Usuario '{usuario}' registrado exitosamente.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Función para autenticar usuarios
def autenticar():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    resultado = autenticar_usuario(usuario, contrasena)
    if resultado == "Autenticación exitosa":
        messagebox.showinfo("Autenticación", resultado)
        abrir_ventana_mensajes()  # Abre una nueva ventana para mensajes
    else:
        messagebox.showwarning("Autenticación", resultado)


# Función para borrar un usuario de la base de datos
def borrar_usuario():
    usuario = usuario_var.get()
    contrasena = contrasena_var.get()
    resultado = autenticar_usuario(usuario, contrasena)
    if resultado == "Autenticación exitosa":
        try:
            conexion = sqlite3.connect(DB_PATH)
            cursor = conexion.cursor()
            cursor.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))
            conexion.commit()
            conexion.close()
            messagebox.showinfo("Borrar Usuario", f"Usuario '{usuario}' ha sido eliminado.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Autenticación Fallida", "Usuario o contraseña incorrectos.")


# Crear y configurar la ventana para la administración de mensajes
def abrir_ventana_mensajes():
    ventana_mensajes = Toplevel(root)
    ventana_mensajes.title("Sistema de Seguridad del Hospital - Cifrado de Mensajes")
    ventana_mensajes.geometry("400x600")
    ventana_mensajes.configure(bg="#f0f4f8")

    # Campo y botón para cifrar y autenticar mensajes
    tk.Label(ventana_mensajes, text="Mensaje para cifrar/autenticar", bg="#f0f4f8", font=("Arial", 12)).pack(pady=10)
    tk.Entry(ventana_mensajes, textvariable=mensaje_var, width=40).pack(pady=5)

    tk.Button(ventana_mensajes, text="Cifrar Mensaje", command=cifrar_mensaje, bg="#007bff", fg="white", width=20).pack(pady=10)

    # Campo y botones para gestionar mensajes por ID (descifrar, autenticar, verificar)
    tk.Label(ventana_mensajes, text="ID del mensaje para descifrar/verificar", bg="#f0f4f8", font=("Arial", 12)).pack(pady=10)
    tk.Entry(ventana_mensajes, textvariable=mensaje_id_var, width=40).pack(pady=5)

    tk.Button(ventana_mensajes, text="Descifrar Mensaje", command=descifrar_mensaje, bg="#007bff", fg="white", width=20).pack(pady=5)
    tk.Button(ventana_mensajes, text="Autenticar Mensaje (HMAC)", command=autenticar_mensaje, bg="#007bff", fg="white", width=20).pack(
        pady=5)
    tk.Button(ventana_mensajes, text="Verificar Autenticidad", command=verificar_autenticidad, bg="#007bff", fg="white", width=20).pack(
        pady=5)

    # Botones de limpieza de la base de datos en la ventana de mensajes
    tk.Label(ventana_mensajes, text="", bg="#f0f4f8").pack()
    tk.Button(ventana_mensajes, text="Limpiar Usuarios", command=limpiar_usuarios, bg="red", fg="white", width=20).pack(pady=(20, 5))
    tk.Button(ventana_mensajes, text="Limpiar Mensajes Cifrados", command=limpiar_mensajes_cifrados, bg="red", fg="white", width=20).pack(
        pady=5)
    tk.Button(ventana_mensajes, text="Limpiar Mensajes Autenticados", command=limpiar_mensajes_autenticados, bg="red", fg="white",
              width=20).pack(pady=5)

    # Botón de salida para cerrar la ventana de mensajes
    tk.Button(ventana_mensajes, text="Salir", command=ventana_mensajes.destroy, bg="yellow", fg="black", width=20).pack(pady=(20, 0))


# Funciones de cifrado y autenticación de mensajes
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


# Funciones para limpiar tablas específicas en la base de datos
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


# Elementos de la interfaz para registro, autenticación y eliminación de usuarios
tk.Label(root, text="Usuario", font=("Arial", 12)).pack(pady=5)
tk.Entry(root, textvariable=usuario_var, width=40).pack(pady=5)

tk.Label(root, text="Contraseña", font=("Arial", 12)).pack(pady=5)
tk.Entry(root, textvariable=contrasena_var, show="*", width=40).pack(pady=5)

tk.Button(root, text="Registrar", command=registrar, bg="blue", fg="white", width=20).pack(pady=5)
tk.Button(root, text="Autenticar", command=autenticar, bg="green", fg="white", width=20).pack(pady=5)
tk.Button(root, text="Borrar Usuario", command=borrar_usuario, bg="red", fg="white", width=20).pack(pady=(10, 20))

# Botón de "Salir" en la ventana principal
tk.Button(root, text="Salir", command=root.quit, bg="yellow", fg="black", width=20).pack()

# Iniciar la aplicación
root.mainloop()
