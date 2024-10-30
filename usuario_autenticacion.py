import sqlite3  # Librería para manejar la base de datos SQLite

import bcrypt  # Librería para hashing seguro de contraseñas

# Ruta de la base de datos SQLite donde se almacenarán los usuarios
DB_PATH = "hospital.db"


# Inicializar la base de datos y crear la tabla de usuarios si no existe
def inicializar_bd():
    """
    Inicializa la base de datos hospital.db y crea la tabla 'usuarios' si no existe.
    La tabla 'usuarios' tiene dos columnas:
    - usuario: Texto que actúa como clave primaria
    - contraseña: Hash de la contraseña del usuario
    """
    conexion = sqlite3.connect(DB_PATH)  # Conectar a la base de datos
    cursor = conexion.cursor()  # Crear un cursor para ejecutar comandos SQL
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            usuario TEXT PRIMARY KEY,
            contraseña TEXT NOT NULL
        )
    ''')
    conexion.commit()  # Guardar cambios en la base de datos
    conexion.close()  # Cerrar la conexión


# Función para leer todos los usuarios desde la base de datos
def leer_usuarios():
    """
    Lee todos los usuarios y sus contraseñas (hashes) desde la base de datos y los devuelve en un diccionario.
    Retorna:
        dict: Un diccionario donde la clave es el nombre de usuario y el valor es el hash de la contraseña.
    """
    conexion = sqlite3.connect(DB_PATH)  # Conectar a la base de datos
    cursor = conexion.cursor()
    cursor.execute("SELECT usuario, contraseña FROM usuarios")  # Obtener todos los usuarios y contraseñas
    usuarios = {row[0]: row[1] for row in cursor.fetchall()}  # Convertir los resultados en un diccionario
    conexion.close()  # Cerrar la conexión
    return usuarios


# Función para registrar un nuevo usuario
def registrar_usuario(usuario, contraseña):
    """
    Registra un nuevo usuario en la base de datos con una contraseña encriptada.
    Si el usuario ya existe, lanza un error.
    Argumentos:
        usuario (str): Nombre de usuario.
        contraseña (str): Contraseña en texto claro.
    """
    usuarios = leer_usuarios()  # Leer todos los usuarios

    if usuario in usuarios:  # Verificar si el usuario ya existe
        raise ValueError("El usuario ya existe.")

    # Generar hash seguro para la contraseña
    hashed = bcrypt.hashpw(contraseña.encode(), bcrypt.gensalt()).decode()

    # Guardar el usuario y la contraseña hasheada en la base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("INSERT INTO usuarios (usuario, contraseña) VALUES (?, ?)", (usuario, hashed))
    conexion.commit()  # Guardar cambios en la base de datos
    conexion.close()  # Cerrar la conexión
    print("Usuario registrado exitosamente.")


# Función para autenticar un usuario
def autenticar_usuario(usuario, contraseña):
    """
    Autentica a un usuario verificando que la contraseña ingresada coincida con el hash almacenado.
    Argumentos:
        usuario (str): Nombre de usuario.
        contraseña (str): Contraseña en texto claro.
    Retorna:
        str: Mensaje indicando si la autenticación fue exitosa o si hubo un error.
    """
    # Conectar a la base de datos y recuperar el hash de la contraseña para el usuario dado
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()
    cursor.execute("SELECT contraseña FROM usuarios WHERE usuario = ?", (usuario,))
    row = cursor.fetchone()  # Obtener el resultado de la consulta
    conexion.close()  # Cerrar la conexión

    if row is None:  # Verificar si el usuario no existe
        return "Usuario no encontrado"

    hashed = row[0].encode()  # Obtener el hash almacenado
    # Comparar la contraseña ingresada con el hash usando bcrypt
    if bcrypt.checkpw(contraseña.encode(), hashed):
        return "Autenticación exitosa"
    else:
        return "Contraseña incorrecta"


# Función para eliminar un usuario de la base de datos
def eliminar_usuario(usuario):
    """
    Elimina un usuario específico de la base de datos.
    Argumentos:
        usuario (str): Nombre de usuario a eliminar.
    """
    conexion = sqlite3.connect(DB_PATH)  # Conectar a la base de datos
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM usuarios WHERE usuario = ?", (usuario,))  # Eliminar el usuario
    conexion.commit()  # Guardar cambios en la base de datos
    conexion.close()  # Cerrar la conexión

    # Confirmar si el usuario fue eliminado
    if cursor.rowcount > 0:
        print("Usuario eliminado exitosamente.")
    else:
        print("Usuario no encontrado.")
