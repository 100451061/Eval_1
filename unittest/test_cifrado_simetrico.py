# unittest/test_cifrado_simetrico.py
import unittest

from Crypto.Random import get_random_bytes

from cifrado_simetrico import cifrar_datos, descifrar_datos


class TestCifradoSimetrico(unittest.TestCase):

    def test_cifrado_y_descifrado(self):
        clave = get_random_bytes(16)  # AES-128 requiere una clave de 16 bytes
        mensaje = "Mensaje de prueba"
        iv, ct = cifrar_datos(mensaje, clave)
        mensaje_descifrado = descifrar_datos(iv, ct, clave)
        self.assertEqual(mensaje, mensaje_descifrado)


if __name__ == '__main__':
    unittest.main()
