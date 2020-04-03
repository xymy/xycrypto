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


# CAST5


class _CAST5(_base.BlockCipher):
    _algorithm = _lib.CAST5
    name = 'CAST5'
    block_size = 8
    key_sizes = frozenset(range(5, 17))


class CAST5(_CAST5):
    pass


class CAST5_ECB(_base.BlockCipherECB, _CAST5):
    pass


class CAST5_CBC(_base.BlockCipherCBC, _CAST5):
    pass


class CAST5_CFB(_base.BlockCipherCFB, _CAST5):
    pass


class CAST5_OFB(_base.BlockCipherOFB, _CAST5):
    pass


# IDEA


class _IDEA(_base.BlockCipher):
    _algorithm = _lib.IDEA
    name = 'IDEA'
    block_size = 8
    key_sizes = frozenset([16])


class IDEA(_IDEA):
    pass


class IDEA_ECB(_base.BlockCipherECB, _IDEA):
    pass


class IDEA_CBC(_base.BlockCipherCBC, _IDEA):
    pass


class IDEA_CFB(_base.BlockCipherCFB, _IDEA):
    pass


class IDEA_OFB(_base.BlockCipherOFB, _IDEA):
    pass


# SEED


class _SEED(_base.BlockCipher):
    _algorithm = _lib.SEED
    name = 'SEED'
    block_size = 16
    key_sizes = frozenset([16])


class SEED(_SEED):
    pass


class SEED_ECB(_base.BlockCipherECB, _SEED):
    pass


class SEED_CBC(_base.BlockCipherCBC, _SEED):
    pass


class SEED_CFB(_base.BlockCipherCFB, _SEED):
    pass


class SEED_OFB(_base.BlockCipherOFB, _SEED):
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
