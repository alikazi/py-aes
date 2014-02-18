import base64

from Crypto.Cipher import AES
from Crypto import Random


RIJNDAEL_KEY = '3255f6ec98cb11e3b7f8a41731c1e4af'


class Rijndael(object):
    """ AES encryption/decryption using PyCrypto along with Base64
    encoding/decoding.
    """

    def __init__(self, secret_key=RIJNDAEL_KEY, block_size=AES.block_size):
        """ Initializes the secret key that is to be shared and used to encrypt
        and decrypt the data.

        @param secret_key: The secret key to use in the symmetric cipher. It
        must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes long.
        @param block_size: Size of a data block (in bytes)
        """
        self.secret_key = secret_key.encode('utf8')
        self.bs = block_size
        # initialization vector which is being used to generate the holy S-Box
        self._iv = Random.new().read(AES.block_size)
        # When the length of input data is not a multiple of 2**n, we need to
        # make it manually as this is not a part of AES-Rijndael algorithm
        # itself and hence, it is not implemented in PyCrypto.
        self._pad_data = lambda s: s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
        self._unpad_data = lambda s: s[0:-ord(s[-1])]

    def encrypt(self, raw_data):
        """
        @param raw_data: This is our raw data which needs to be encrypted.
        """
        try:
            raw_data = raw_data.encode('utf8')
        except AttributeError:
            pass
        else:
            raw_data = self._pad_data(raw_data)
            cipher = AES.new(self.secret_key, AES.MODE_CBC, self._iv)
            # to be more secure, return Base64 encoded version
            return base64.b64encode(self._iv + cipher.encrypt(raw_data))
        return ''

    def decrypt(self, encrypted_data):
        """
        @param encrypted_data: This is our encrypted data. We need to first
        normalize it back from Base64 and then decrypt it using the same secret
        key.
        """
        try:
            # decode it back from Base64 and then decrypt it
            encrypted_data = base64.b64decode(encrypted_data)
            iv = encrypted_data[:AES.block_size]
            cipher = AES.new(self.secret_key, AES.MODE_CBC, iv)
            return self._unpad_data(
                cipher.decrypt(encrypted_data[AES.block_size:])
            )
        except (TypeError, ValueError):
            return ''
