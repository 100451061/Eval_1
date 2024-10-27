import json
import tkinter as tk
from tkinter import messagebox

from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac
from cifrado_simetrico import cifrar_datos, descifrar_datos

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


def abrir_ventana_datos():
    ventana_datos = tk.Toplevel()
    ventana_datos.title("Hospital Gregorio Marañón - Gestión de Datos")
    ventana_datos.geometry("600x700")

    tk.Label(ventana_datos, text="Gestión de Información Médica", font=("Arial", 16, "bold")).pack(pady=10)

    tk.Label(ventana_datos, text="Mensaje a Cifrar/Descifrar:").pack(pady=5)
    global entry_mensaje
    entry_mensaje = tk.Entry(ventana_datos)
    entry_mensaje.pack(pady=5)

    tk.Button(ventana_datos, text="Cifrar Mensaje", command=cifrar_mensaje, bg="lightblue").pack(pady=5)
    tk.Button(ventana_datos, text="Descifrar Mensaje", command=descifrar_mensaje, bg="lightgreen").pack(pady=5)

    tk.Label(ventana_datos, text="IV (Vector de Inicialización):").pack(pady=5)
    global entry_iv
    entry_iv = tk.Entry(ventana_datos)
    entry_iv.pack(pady=5)

    tk.Label(ventana_datos, text="Texto Cifrado:").pack(pady=5)
    global entry_ct
    entry_ct = tk.Entry(ventana_datos)
    entry_ct.pack(pady=5)

    tk.Label(ventana_datos, text="MAC:").pack(pady=5)
    global entry_mac
    entry_mac = tk.Entry(ventana_datos)
    entry_mac.pack(pady=5)

    tk.Button(ventana_datos, text="Generar MAC", command=generar_mac_mensaje, bg="lightblue").pack(pady=5)
    tk.Button(ventana_datos, text="Verificar MAC", command=verificar_mac_mensaje, bg="lightgreen").pack(pady=5)
