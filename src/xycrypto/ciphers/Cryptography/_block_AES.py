from . import _base, _lib


class _AES(_base.BlockCipher):
    _algorithm = _lib.AES
    name = 'AES'
    block_size = 16
    key_sizes = frozenset([16, 24, 32])


class AES(_AES):
    pass


class AES_ECB(_base.BlockCipherECB, _AES):
    pass


class AES_CBC(_base.BlockCipherCBC, _AES):
    pass


class AES_CFB(_base.BlockCipherCFB, _AES):
    pass


class AES_OFB(_base.BlockCipherOFB, _AES):
    pass


class AES_CTR(_base.BlockCipherCTR, _AES):
    pass
