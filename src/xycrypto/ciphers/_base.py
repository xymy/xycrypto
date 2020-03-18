import abc

from . import _lib, _utils


class Cipher(metaclass=abc.ABCMeta):
    """Abstract base class for cipher."""

    @property
    @abc.abstractmethod
    def _algorithm(self):
        """The algorithm of this cipher."""


class StreamCipher(Cipher):
    """Abstract base class for stream cipher."""

    def __init__(self, key):
        self._cipher = _lib.Cipher(self._algorithm(key), None, _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()


class BlockCipher(Cipher):
    """Abstract base class for block cipher."""

    @property
    @abc.abstractmethod
    def block_size(self):
        """The block size in bytes of this cipher."""


class BlockCipherECB(BlockCipher):
    """Abstract base class for block cipher in ECB mode."""

    def __init__(self, key, *, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.ECB(), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)

    def encryptor(self):
        return _utils._determine_encryptor(self._cipher, self._padding)

    def decryptor(self):
        return _utils._determine_decryptor(self._cipher, self._padding)

    @classmethod
    def encrypt(cls, key, data, *, padding='PKCS7'):
        cipher = cls(key, padding=padding)
        return _utils._perform_encryption(cipher, data)

    @classmethod
    def decrypt(cls, key, data, *, padding='PKCS7'):
        cipher = cls(key, padding=padding)
        return _utils._perform_decryption(cipher, data)


class BlockCipherCBC(BlockCipher):
    """Abstract base class for block cipher in CBC mode."""

    def __init__(self, key, *, iv, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CBC(iv), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)

    def encryptor(self):
        return _utils._determine_encryptor(self._cipher, self._padding)

    def decryptor(self):
        return _utils._determine_decryptor(self._cipher, self._padding)

    @classmethod
    def encrypt(cls, key, data, *, iv, padding='PKCS7'):
        cipher = cls(key, iv=iv, padding=padding)
        return _utils._perform_encryption(cipher, data)

    @classmethod
    def decrypt(cls, key, data, *, iv, padding='PKCS7'):
        cipher = cls(key, iv=iv, padding=padding)
        return _utils._perform_decryption(cipher, data)


@StreamCipher.register
class BlockCipherOFB(BlockCipher):
    """Abstract base class for block cipher in OFB mode."""

    def __init__(self, key, *, iv):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.OFB(iv), _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()

    @classmethod
    def encrypt(cls, key, data, *, iv):
        cipher = cls(key, iv=iv)
        return _utils._perform_encryption(cipher, data)

    @classmethod
    def decrypt(cls, key, data, *, iv):
        cipher = cls(key, iv=iv)
        return _utils._perform_decryption(cipher, data)


@StreamCipher.register
class BlockCipherCFB(BlockCipher):
    """Abstract base class for block cipher in CFB mode."""

    def __init__(self, key, *, iv):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CFB(iv), _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()

    @classmethod
    def encrypt(cls, key, data, *, iv):
        cipher = cls(key, iv=iv)
        return _utils._perform_encryption(cipher, data)

    @classmethod
    def decrypt(cls, key, data, *, iv):
        cipher = cls(key, iv=iv)
        return _utils._perform_decryption(cipher, data)


@StreamCipher.register
class BlockCipherCTR(BlockCipher):
    """Abstract base class for block cipher in CTR mode."""

    def __init__(self, key, *, nonce):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CTR(nonce), _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()

    @classmethod
    def encrypt(cls, key, data, *, nonce):
        cipher = cls(key, nonce=nonce)
        return _utils._perform_encryption(cipher, data)

    @classmethod
    def decrypt(cls, key, data, *, nonce):
        cipher = cls(key, nonce=nonce)
        return _utils._perform_decryption(cipher, data)
