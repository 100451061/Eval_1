# unittest/test_autenticacion_mensajes.py
import unittest

from Crypto.Random import get_random_bytes

from autenticacion_mensajes import generar_mac, verificar_mac


class TestAutenticacionMensajes(unittest.TestCase):

    def test_generar_y_verificar_mac(self):
        clave = get_random_bytes(16)
        mensaje = "Mensaje para MAC"
        mac = generar_mac(mensaje, clave)
        es_valido = verificar_mac(mensaje, mac, clave)
        self.assertTrue(es_valido)

    def test_mac_incorrecto(self):
        clave = get_random_bytes(16)
        mensaje = "Mensaje para MAC"
        mac = generar_mac(mensaje, clave)
        clave_incorrecta = get_random_bytes(16)
        es_valido = verificar_mac(mensaje, mac, clave_incorrecta)
        self.assertFalse(es_valido)


if __name__ == '__main__':
    unittest.main()
