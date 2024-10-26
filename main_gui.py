# archivo: main_gui.py
import json
import tkinter as tk
from tkinter import messagebox

from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac
from cifrado_simetrico import cifrar_datos, descifrar_datos
from usuario_autenticacion import guardar_usuario, autenticar_usuario, borrar_usuario

# Clave de cifrado simétrica para pruebas
clave_simetrica = get_random_bytes(16)

# Ruta del archivo de mensajes cifrados
RUTA_MENSAJES_CIFRADOS = "mensajes_cifrados.json"


# Función para limpiar el archivo de mensajes cifrados
def limpiar_mensajes_cifrados():
    with open(RUTA_MENSAJES_CIFRADOS, 'w') as file:
        json.dump([], file)  # Guarda una lista vacía para iniciar desde cero


# Llamamos a esta función al iniciar la aplicación para limpiar el archivo de mensajes
limpiar_mensajes_cifrados()


# Función para guardar un mensaje cifrado en el archivo JSON
def guardar_mensaje_cifrado(iv, ct):
    try:
        with open(RUTA_MENSAJES_CIFRADOS, 'r+') as file:
            datos = json.load(file)
            nuevo_mensaje = {"IV": iv, "Texto Cifrado": ct}
            if nuevo_mensaje not in datos:
                datos.append(nuevo_mensaje)
                file.seek(0)
                json.dump(datos, file, indent=4)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(RUTA_MENSAJES_CIFRADOS, 'w') as file:
            json.dump([{"IV": iv, "Texto Cifrado": ct}], file, indent=4)


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
    messagebox.showinfo("Autenticación", resultado)


def borrar():
    usuario = entry_usuario.get()
    if usuario:
        resultado = borrar_usuario(usuario)
        messagebox.showinfo("Eliminar Usuario", resultado)
    else:
        messagebox.showerror("Error", "El campo de usuario es obligatorio para borrar.")


def cifrar_mensaje():
    mensaje = entry_mensaje.get()
    if mensaje:
        iv, ct = cifrar_datos(mensaje, clave_simetrica)
        entry_iv.delete(0, tk.END)
        entry_ct.delete(0, tk.END)
        entry_iv.insert(0, iv)
        entry_ct.insert(0, ct)
        guardar_mensaje_cifrado(iv, ct)
        messagebox.showinfo("Cifrado", "Mensaje cifrado correctamente.")
    else:
        messagebox.showerror("Error", "El campo de mensaje no puede estar vacío.")


def descifrar_mensaje():
    iv = entry_iv.get()
    ct = entry_ct.get()
    if iv and ct:
        try:
            mensaje_descifrado = descifrar_datos(iv, ct, clave_simetrica)
            messagebox.showinfo("Descifrado", f"Mensaje descifrado: {mensaje_descifrado}")
        except Exception as e:
            messagebox.showerror("Error", f"Fallo en el descifrado: {str(e)}")
    else:
        messagebox.showerror("Error", "El IV y el Texto Cifrado son obligatorios para descifrar.")


def generar_mac_mensaje():
    mensaje = entry_mensaje.get()
    if mensaje:
        mac = generar_mac(mensaje, clave_simetrica)
        entry_mac.delete(0, tk.END)
        entry_mac.insert(0, mac)
        messagebox.showinfo("MAC", "MAC generado correctamente.")
    else:
        messagebox.showerror("Error", "El campo de mensaje no puede estar vacío.")


def verificar_mac_mensaje():
    mensaje = entry_mensaje.get()
    mac = entry_mac.get()
    if mensaje and mac:
        es_valido = verificar_mac(mensaje, mac, clave_simetrica)
        resultado = "MAC válido" if es_valido else "MAC no válido"
        messagebox.showinfo("Verificación MAC", resultado)
    else:
        messagebox.showerror("Error", "El Mensaje y el MAC son obligatorios para la verificación.")


if __name__ == '__main__':
    root = tk.Tk()
    root.title("Aplicación de Seguridad y Criptografía")
    root.geometry("700x700")

    # Sección de Autenticación
    tk.Label(root, text="Usuario:").pack(pady=5)
    entry_usuario = tk.Entry(root)
    entry_usuario.pack(pady=5)

    tk.Label(root, text="Contraseña:").pack(pady=5)
    entry_contraseña = tk.Entry(root, show="*")
    entry_contraseña.pack(pady=5)

    tk.Button(root, text="Registrar Usuario", command=registrar_usuario).pack(pady=5)
    tk.Button(root, text="Autenticar Usuario", command=autenticar).pack(pady=5)
    tk.Button(root, text="Borrar Usuario", command=borrar).pack(pady=5)

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

    # Sección de MAC
    tk.Button(root, text="Generar MAC", command=generar_mac_mensaje).pack(pady=5)
    tk.Label(root, text="MAC:").pack(pady=5)
    entry_mac = tk.Entry(root)
    entry_mac.pack(pady=5)

    tk.Button(root, text="Verificar MAC", command=verificar_mac_mensaje).pack(pady=5)

    # Iniciar la ventana
    root.mainloop()
