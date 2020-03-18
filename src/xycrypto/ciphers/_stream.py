from . import _base, _lib


class ARC4(_base.StreamCipher):
    _algorithm = _lib.ARC4
    name = 'ARC4'


class ChaCha20(_base.StreamCipher):
    _algorithm = _lib.ChaCha20
    name = 'ChaCha20'
