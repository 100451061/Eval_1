import unittest

from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac


class TestAutenticacionMensajes(unittest.TestCase):

    def setUp(self):
        self.clave = get_random_bytes(16)
        self.mensaje = "Mensaje de prueba"
        self.mac = generar_mac(self.mensaje, self.clave)

    def test_generar_mac(self):
        mac_generada = generar_mac(self.mensaje, self.clave)
        self.assertEqual(self.mac, mac_generada)

    def test_verificar_mac_valida(self):
        self.assertTrue(verificar_mac(self.mensaje, self.mac, self.clave))

    def test_verificar_mac_invalida(self):
        mac_invalida = generar_mac("Otro mensaje", self.clave)
        self.assertFalse(verificar_mac(self.mensaje, mac_invalida, self.clave))


if __name__ == '__main__':
    unittest.main()
