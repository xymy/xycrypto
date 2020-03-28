from . import _base, _lib


class ChaCha20(_base.StreamCipher):
    _algorithm = _lib.ChaCha20
    name = 'ChaCha20'
    key_sizes = frozenset([32])

    def __init__(self, key, *, nonce):
        self._cipher = _lib.Cipher(self._algorithm(key, nonce), None, _lib.backend)


class RC4(_base.StreamCipher):
    _algorithm = _lib.ARC4
    name = 'RC4'
    key_sizes = frozenset([5, 7, 8, 10, 16, 20, 24, 32])
