import abc

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
        self.cipher = _lib.Cipher(self._algorithm(key), mode, _lib.backend)
        if padding is not None:
            self.padding = padding(self.block_size)


class StreamCipher(Cipher):
    def __init__(self, key):
        self.cipher = _lib.Cipher(self._algorithm(key), None, _lib.backend)
