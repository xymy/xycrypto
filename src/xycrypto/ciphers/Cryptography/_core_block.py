from . import _base, _lib


# AES


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


# Blowfish


class _Blowfish(_base.BlockCipher):
    _algorithm = _lib.Blowfish
    name = 'Blowfish'
    block_size = 8
    key_sizes = frozenset(range(4, 57))


class Blowfish(_Blowfish):
    pass


class Blowfish_ECB(_base.BlockCipherECB, _Blowfish):
    pass


class Blowfish_CBC(_base.BlockCipherCBC, _Blowfish):
    pass


class Blowfish_CFB(_base.BlockCipherCFB, _Blowfish):
    pass


class Blowfish_OFB(_base.BlockCipherOFB, _Blowfish):
    pass


# Camellia


class _Camellia(_base.BlockCipher):
    _algorithm = _lib.Camellia
    name = 'Camellia'
    block_size = 16
    key_sizes = frozenset([16, 24, 32])


class Camellia(_Camellia):
    pass


class Camellia_ECB(_base.BlockCipherECB, _Camellia):
    pass


class Camellia_CBC(_base.BlockCipherCBC, _Camellia):
    pass


class Camellia_CFB(_base.BlockCipherCFB, _Camellia):
    pass


class Camellia_OFB(_base.BlockCipherOFB, _Camellia):
    pass


class Camellia_CTR(_base.BlockCipherCTR, _Camellia):
    pass


# 3DES


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