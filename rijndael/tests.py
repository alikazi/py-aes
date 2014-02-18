import unittest

from rijndael import Rijndael


class AESRijndaelTest(unittest.TestCase):
    """ Tests for AESRijndael
    """

    def setUp(self):
        self.encrypt_obj = Rijndael()
        self.decrypt_obj = Rijndael()
        self.data = 'this is my test data to encrypt'

    def test_encrypt(self):
        encrypted_data = self.encrypt_obj.encrypt(self.data)
        self.assertNotEqual(self.data, encrypted_data)

    def test_decrypt(self):
        encrypted_data = self.encrypt_obj.encrypt(self.data)
        decrypted_data = self.decrypt_obj.decrypt(encrypted_data)
        self.assertEqual(self.data, decrypted_data)


if __name__ == '__main__':
    unittest.main()