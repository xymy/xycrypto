import abc

from . import _lib
from . import _utils


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

    def __init__(self, key, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.ECB(), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)

    def encryptor(self):
        return _utils._determine_encryptor(self._cipher, self._padding)

    def decryptor(self):
        return _utils._determine_decryptor(self._cipher, self._padding)


class BlockCipherCBC(BlockCipher):
    """Abstract base class for block cipher in CBC mode."""

    def __init__(self, key, iv, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CBC(iv), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)

    def encryptor(self):
        return _utils._determine_encryptor(self._cipher, self._padding)

    def decryptor(self):
        return _utils._determine_decryptor(self._cipher, self._padding)
