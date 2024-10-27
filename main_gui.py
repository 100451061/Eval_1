import json
import tkinter as tk
from tkinter import messagebox, scrolledtext

from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac
from cifrado_simetrico import cifrar_datos, descifrar_datos
from usuario_autenticacion import guardar_usuario, autenticar_usuario, borrar_usuario

# Clave de cifrado para datos médicos
clave_simetrica = get_random_bytes(16)
RUTA_MENSAJES_CIFRADOS = "mensajes_cifrados.json"


def limpiar_mensajes_cifrados():
    with open(RUTA_MENSAJES_CIFRADOS, 'w') as file:
        json.dump([], file)


limpiar_mensajes_cifrados()


def guardar_mensaje_cifrado(iv, ct):
    with open(RUTA_MENSAJES_CIFRADOS, 'r+') as file:
        datos = json.load(file)
        nuevo_mensaje = {"IV": iv, "Texto Cifrado": ct}
        if nuevo_mensaje not in datos:
            datos.append(nuevo_mensaje)
            file.seek(0)
            json.dump(datos, file, indent=4)


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


def cifrar_mensaje():
    mensaje = entry_mensaje.get()
    if mensaje:
        iv, ct = cifrar_datos(mensaje, clave_simetrica)
        entry_iv.delete(0, tk.END)
        entry_ct.delete(0, tk.END)
        entry_iv.insert(0, iv)
        entry_ct.insert(0, ct)
        guardar_mensaje_cifrado(iv, ct)
        message_log.insert(tk.END, "Mensaje cifrado correctamente.\n")
    else:
        message_log.insert(tk.END, "Error: El campo de mensaje no puede estar vacío.\n")


def descifrar_mensaje():
    iv = entry_iv.get()
    ct = entry_ct.get()
    if iv and ct:
        try:
            mensaje_descifrado = descifrar_datos(iv, ct, clave_simetrica)
            message_log.insert(tk.END, f"Mensaje descifrado: {mensaje_descifrado}\n")
        except Exception as e:
            message_log.insert(tk.END, f"Error en descifrado: {str(e)}\n")
    else:
        message_log.insert(tk.END, "Error: El IV y el Texto Cifrado son obligatorios para descifrar.\n")


def generar_mac_mensaje():
    mensaje = entry_mensaje.get()
    if mensaje:
        mac = generar_mac(mensaje, clave_simetrica)
        entry_mac.delete(0, tk.END)
        entry_mac.insert(0, mac)
        message_log.insert(tk.END, "MAC generado correctamente.\n")
    else:
        message_log.insert(tk.END, "Error: El campo de mensaje no puede estar vacío.\n")


def verificar_mac_mensaje():
    mensaje = entry_mensaje.get()
    mac = entry_mac.get()
    if mensaje and mac:
        es_valido = verificar_mac(mensaje, mac, clave_simetrica)
        resultado = "MAC válido" if es_valido else "MAC no válido"
        message_log.insert(tk.END, f"Verificación de MAC: {resultado}\n")
    else:
        message_log.insert(tk.END, "Error: El Mensaje y el MAC son obligatorios para la verificación.\n")


def abrir_ventana_datos():
    ventana_datos = tk.Toplevel()
    ventana_datos.title("Hospital Gregorio Marañón - Gestión de Datos")
    ventana_datos.geometry("600x750")

    tk.Label(ventana_datos, text="Gestión de Información Médica", font=("Arial", 16, "bold")).pack(pady=10)

    tk.Label(ventana_datos, text="Mensaje a Cifrar/Descifrar:").pack(pady=5)
    global entry_mensaje
    entry_mensaje = tk.Entry(ventana_datos, width=60)
    entry_mensaje.pack(pady=5)

    tk.Button(ventana_datos, text="Cifrar Mensaje", command=cifrar_mensaje, bg="lightblue").pack(pady=5)
    tk.Button(ventana_datos, text="Descifrar Mensaje", command=descifrar_mensaje, bg="lightgreen").pack(pady=5)

    tk.Label(ventana_datos, text="IV (Vector de Inicialización):").pack(pady=5)
    global entry_iv
    entry_iv = tk.Entry(ventana_datos, width=60)
    entry_iv.pack(pady=5)

    tk.Label(ventana_datos, text="Texto Cifrado:").pack(pady=5)
    global entry_ct
    entry_ct = tk.Entry(ventana_datos, width=60)
    entry_ct.pack(pady=5)

    tk.Label(ventana_datos, text="MAC:").pack(pady=5)
    global entry_mac
    entry_mac = tk.Entry(ventana_datos, width=60)
    entry_mac.pack(pady=5)

    tk.Button(ventana_datos, text="Generar MAC", command=generar_mac_mensaje, bg="lightblue").pack(pady=5)
    tk.Button(ventana_datos, text="Verificar MAC", command=verificar_mac_mensaje, bg="lightgreen").pack(pady=5)

    tk.Label(ventana_datos, text="Registro de Operaciones", font=("Arial", 12, "bold")).pack(pady=5)
    global message_log
    message_log = scrolledtext.ScrolledText(ventana_datos, width=70, height=10, wrap=tk.WORD)
    message_log.pack(pady=10)
    message_log.insert(tk.END, "Aquí se mostrarán las operaciones realizadas.\n")

    # Botón para limpiar el área de registro de operaciones
    tk.Button(ventana_datos, text="Limpiar Registro", command=lambda: message_log.delete('1.0', tk.END)).pack(pady=5)


# Ventana de inicio
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
