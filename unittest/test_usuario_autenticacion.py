# unittest/test_usuario_autenticacion.py
import unittest

from usuario_autenticacion import guardar_usuario, autenticar_usuario


class TestUsuarioAutenticacion(unittest.TestCase):

    def test_guardar_usuario(self):
        guardar_usuario("testuser", "password123")
        resultado = autenticar_usuario("testuser", "password123")
        self.assertEqual(resultado, "Autenticación exitosa")

    def test_autenticar_usuario_incorrecto(self):
        guardar_usuario("testuser", "password123")
        resultado = autenticar_usuario("testuser", "wrongpassword")
        self.assertEqual(resultado, "Contraseña incorrecta")

    def test_usuario_no_encontrado(self):
        resultado = autenticar_usuario("nouser", "password123")
        self.assertEqual(resultado, "Usuario no encontrado")


if __name__ == '__main__':
    unittest.main()
