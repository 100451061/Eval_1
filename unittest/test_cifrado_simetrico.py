import unittest

from Crypto.Random import get_random_bytes

from cifrado_simetrico import cifrar_datos, descifrar_datos


class TestCifradoSimetrico(unittest.TestCase):

    def setUp(self):
        self.clave = get_random_bytes(16)
        self.mensaje = "Mensaje de prueba"
        self.iv, self.ct = cifrar_datos(self.mensaje, self.clave)

    def test_cifrado(self):
        self.assertIsNotNone(self.iv)
        self.assertIsNotNone(self.ct)

    def test_descifrado(self):
        mensaje_descifrado = descifrar_datos(self.iv, self.ct, self.clave)
        self.assertEqual(self.mensaje, mensaje_descifrado)

    def test_descifrado_invalido(self):
        with self.assertRaises(ValueError):
            descifrar_datos("iv_invalido", "ct_invalido", self.clave)


if __name__ == '__main__':
    unittest.main()
