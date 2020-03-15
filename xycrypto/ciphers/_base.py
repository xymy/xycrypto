import abc

from xycrypto.padding import _lookup_padding

from . import _lib


class Cipher(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def _algorithm(self):
        """The cipher algorithm."""


class BlockCipher(Cipher):
    @property
    @abc.abstractmethod
    def block_size(self):
        """The block size in bytes of this cipher."""

    def __init__(self, key, mode, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), mode, _lib.backend)
        if padding is None:
            self._padding = None
        else:
            padding = _lookup_padding(padding)
            self._padding = padding(self.block_size)

    def encryptor(self):
        encryptor = self._cipher.encryptor()
        if self._padding is None:
            return encryptor
        return self._padding.wrap_encryptor(encryptor)

    def decryptor(self):
        decryptor = self._cipher.decryptor()
        if self._padding is None:
            return decryptor
        return self._padding.wrap_decryptor(decryptor)


class StreamCipher(Cipher):
    def __init__(self, key):
        self._cipher = _lib.Cipher(self._algorithm(key), None, _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()
