import tkinter as tk
from tkinter import messagebox

from gestion_datos import abrir_ventana_datos  # Función para abrir la ventana de datos

from usuario_autenticacion import guardar_usuario, autenticar_usuario, borrar_usuario


def registrar_usuario():
    usuario = entry_usuario.get()
    contraseña = entry_contraseña.get()
    if usuario and contraseña:
        guardar_usuario(usuario, contraseña)
        messagebox.showinfo("Registro", "Usuario registrado exitosamente.")
    else:
        messagebox.showerror("Error", "Ambos campos son obligatorios.")


def autenticar():
    usuario = entry_usuario.get()
    contraseña = entry_contraseña.get()
    resultado = autenticar_usuario(usuario, contraseña)
    if resultado == "Autenticación exitosa":
        root.withdraw()  # Cierra la ventana de inicio de sesión
        abrir_ventana_datos()  # Abre la ventana de gestión de datos
    else:
        messagebox.showerror("Error", "Usuario o contraseña incorrecta.")


def borrar():
    usuario = entry_usuario.get()
    if usuario:
        resultado = borrar_usuario(usuario)
        messagebox.showinfo("Eliminar Usuario", resultado)
    else:
        messagebox.showerror("Error", "El campo de usuario es obligatorio para borrar.")


if __name__ == '__main__':
    root = tk.Tk()
    root.title("Hospital Gregorio Marañón - Inicio de Sesión")
    root.geometry("400x300")

    tk.Label(root, text="Inicio de Sesión", font=("Arial", 16, "bold")).pack(pady=10)

    tk.Label(root, text="Usuario:").pack(pady=5)
    entry_usuario = tk.Entry(root)
    entry_usuario.pack(pady=5)

    tk.Label(root, text="Contraseña:").pack(pady=5)
    entry_contraseña = tk.Entry(root, show="*")
    entry_contraseña.pack(pady=5)

    tk.Button(root, text="Registrar Usuario", command=registrar_usuario, bg="lightblue").pack(pady=5)
    tk.Button(root, text="Autenticar Usuario", command=autenticar, bg="lightgreen").pack(pady=5)
    tk.Button(root, text="Borrar Usuario", command=borrar, bg="lightcoral").pack(pady=5)

    root.mainloop()
