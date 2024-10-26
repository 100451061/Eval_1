# main_gui.py
import tkinter as tk
from tkinter import messagebox

from cifrado_simetrico import cifrar_datos, descifrar_datos
from usuario_autenticacion import guardar_usuario, autenticar_usuario, derivar_clave


def registrar_usuario():
    usuario = entry_usuario.get()
    password = entry_contraseña.get()
    if usuario and password:
        guardar_usuario(usuario, password)
        messagebox.showinfo("Registro", "Usuario registrado exitosamente.")
    else:
        messagebox.showerror("Error", "Ambos campos son obligatorios.")


def autenticar():
    usuario = entry_usuario.get()
    password = entry_contraseña.get()
    resultado = autenticar_usuario(usuario, password)
    messagebox.showinfo("Autenticación", resultado)
    return resultado == "Autenticación exitosa"


def cifrar_mensaje():
    usuario = entry_usuario.get()
    password = entry_contraseña.get()
    if autenticar():
        key, _ = derivar_clave(password)  # Deriva la clave
        mensaje = entry_mensaje.get()
        iv, ct, tag = cifrar_datos(mensaje, key)
        entry_iv.delete(0, tk.END)
        entry_ct.delete(0, tk.END)
        entry_tag.delete(0, tk.END)
        entry_iv.insert(0, iv)
        entry_ct.insert(0, ct)
        entry_tag.insert(0, tag)
        messagebox.showinfo("Cifrado", "Mensaje cifrado correctamente.")


def descifrar_mensaje():
    usuario = entry_usuario.get()
    password = entry_contraseña.get()
    if autenticar():
        key, _ = derivar_clave(password)  # Deriva la clave
        iv = entry_iv.get()
        ct = entry_ct.get()
        tag = entry_tag.get()
        try:
            mensaje_descifrado = descifrar_datos(iv, ct, tag, key)
            messagebox.showinfo("Descifrado", f"Mensaje descifrado: {mensaje_descifrado}")
        except Exception as e:
            messagebox.showerror("Error", f"Fallo en el descifrado: {str(e)}")


if __name__ == '__main__':
    # Interfaz gráfica
    root = tk.Tk()
    root.title("Aplicación de Seguridad y Criptografía")
    root.geometry("500x600")

    # Sección de Autenticación
    tk.Label(root, text="Usuario:").pack(pady=5)
    entry_usuario = tk.Entry(root)
    entry_usuario.pack(pady=5)

    tk.Label(root, text="Contraseña:").pack(pady=5)
    entry_contraseña = tk.Entry(root, show="*")
    entry_contraseña.pack(pady=5)

    tk.Button(root, text="Registrar Usuario", command=registrar_usuario).pack(pady=5)
    tk.Button(root, text="Autenticar Usuario", command=autenticar).pack(pady=5)

    # Sección de Cifrado
    tk.Label(root, text="Mensaje a Cifrar/Descifrar:").pack(pady=5)
    entry_mensaje = tk.Entry(root)
    entry_mensaje.pack(pady=5)

    tk.Button(root, text="Cifrar Mensaje", command=cifrar_mensaje).pack(pady=5)
    tk.Button(root, text="Descifrar Mensaje", command=descifrar_mensaje).pack(pady=5)

    tk.Label(root, text="IV (Vector de Inicialización):").pack(pady=5)
    entry_iv = tk.Entry(root)
    entry_iv.pack(pady=5)

    tk.Label(root, text="Texto Cifrado:").pack(pady=5)
    entry_ct = tk.Entry(root)
    entry_ct.pack(pady=5)

    tk.Label(root, text="Etiqueta de Autenticación (Tag):").pack(pady=5)
    entry_tag = tk.Entry(root)
    entry_tag.pack(pady=5)

    # Iniciar la ventana
    root.mainloop()
