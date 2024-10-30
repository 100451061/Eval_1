import tkinter as tk
from tkinter import messagebox

from autenticacion_mensajes import almacenar_mensaje, verificar_mensaje
from cifrado_simetrico import almacenar_datos_cifrados, descifrar_datos
# Importar las funciones de los otros archivos
from usuario_autenticacion import registrar_usuario, autenticar_usuario

# Ruta de la base de datos
DB_PATH = "hospital.db"

# Crear la ventana principal
root = tk.Tk()
root.title("Sistema de Seguridad del Hospital")
root.geometry("400x500")

# Variables para los campos de entrada
usuario_var = tk.StringVar()
contrasena_var = tk.StringVar()
mensaje_var = tk.StringVar()
mensaje_id_var = tk.StringVar()


# Funciones de la GUI
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
    messagebox.showinfo("Autenticación", resultado)


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


# Elementos de la GUI
tk.Label(root, text="Usuario").pack()
tk.Entry(root, textvariable=usuario_var).pack()

tk.Label(root, text="Contraseña").pack()
tk.Entry(root, textvariable=contrasena_var, show="*").pack()

tk.Button(root, text="Registrar", command=registrar).pack()
tk.Button(root, text="Autenticar", command=autenticar).pack()

tk.Label(root, text="Mensaje para cifrar/autenticar").pack()
tk.Entry(root, textvariable=mensaje_var).pack()

tk.Button(root, text="Cifrar Mensaje", command=cifrar_mensaje).pack()

tk.Label(root, text="ID del mensaje para descifrar/verificar").pack()
tk.Entry(root, textvariable=mensaje_id_var).pack()

tk.Button(root, text="Descifrar Mensaje", command=descifrar_mensaje).pack()
tk.Button(root, text="Autenticar Mensaje (HMAC)", command=autenticar_mensaje).pack()
tk.Button(root, text="Verificar Autenticidad", command=verificar_autenticidad).pack()

# Iniciar la aplicación
root.mainloop()
