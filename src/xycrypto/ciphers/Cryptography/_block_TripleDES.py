from . import _base, _lib


class _TripleDES(_base.BlockCipher):
    _algorithm = _lib.TripleDES
    name = '3DES'
    block_size = 8
    key_sizes = frozenset([8, 16, 24])


class TripleDES(_TripleDES):
    pass


class TripleDES_ECB(_base.BlockCipherECB, _TripleDES):
    pass


class TripleDES_CBC(_base.BlockCipherCBC, _TripleDES):
    pass


class TripleDES_CFB(_base.BlockCipherCFB, _TripleDES):
    pass


class TripleDES_OFB(_base.BlockCipherOFB, _TripleDES):
    pass
