from . import _base, _lib


# AES


class AES(_base.BlockCipher):
    _algorithm = _lib.AES
    name = 'AES'
    block_size = 16
    key_sizes = frozenset([16, 24, 32])


class AES_ECB(_base.BlockCipherECB, AES):
    pass


class AES_CBC(_base.BlockCipherCBC, AES):
    pass


class AES_CFB(_base.BlockCipherCFB, AES):
    pass


class AES_OFB(_base.BlockCipherOFB, AES):
    pass


class AES_CTR(_base.BlockCipherCTR, AES):
    pass


# Blowfish


class Blowfish(_base.BlockCipher):
    _algorithm = _lib.Blowfish
    name = 'Blowfish'
    block_size = 8
    key_sizes = frozenset(range(4, 57))


class Blowfish_ECB(_base.BlockCipherECB, Blowfish):
    pass


class Blowfish_CBC(_base.BlockCipherCBC, Blowfish):
    pass


class Blowfish_CFB(_base.BlockCipherCFB, Blowfish):
    pass


class Blowfish_OFB(_base.BlockCipherOFB, Blowfish):
    pass


# Camellia


class Camellia(_base.BlockCipher):
    _algorithm = _lib.Camellia
    name = 'Camellia'
    block_size = 16
    key_sizes = frozenset([16, 24, 32])


class Camellia_ECB(_base.BlockCipherECB, Camellia):
    pass


class Camellia_CBC(_base.BlockCipherCBC, Camellia):
    pass


class Camellia_CFB(_base.BlockCipherCFB, Camellia):
    pass


class Camellia_OFB(_base.BlockCipherOFB, Camellia):
    pass


class Camellia_CTR(_base.BlockCipherCTR, Camellia):
    pass


# CAST5


class CAST5(_base.BlockCipher):
    _algorithm = _lib.CAST5
    name = 'CAST5'
    block_size = 8
    key_sizes = frozenset(range(5, 17))


class CAST5_ECB(_base.BlockCipherECB, CAST5):
    pass


class CAST5_CBC(_base.BlockCipherCBC, CAST5):
    pass


class CAST5_CFB(_base.BlockCipherCFB, CAST5):
    pass


class CAST5_OFB(_base.BlockCipherOFB, CAST5):
    pass


# IDEA


class IDEA(_base.BlockCipher):
    _algorithm = _lib.IDEA
    name = 'IDEA'
    block_size = 8
    key_sizes = frozenset([16])


class IDEA_ECB(_base.BlockCipherECB, IDEA):
    pass


class IDEA_CBC(_base.BlockCipherCBC, IDEA):
    pass


class IDEA_CFB(_base.BlockCipherCFB, IDEA):
    pass


class IDEA_OFB(_base.BlockCipherOFB, IDEA):
    pass


# SEED


class SEED(_base.BlockCipher):
    _algorithm = _lib.SEED
    name = 'SEED'
    block_size = 16
    key_sizes = frozenset([16])


class SEED_ECB(_base.BlockCipherECB, SEED):
    pass


class SEED_CBC(_base.BlockCipherCBC, SEED):
    pass


class SEED_CFB(_base.BlockCipherCFB, SEED):
    pass


class SEED_OFB(_base.BlockCipherOFB, SEED):
    pass


# 3DES


class TripleDES(_base.BlockCipher):
    _algorithm = _lib.TripleDES
    name = '3DES'
    block_size = 8
    key_sizes = frozenset([8, 16, 24])


class TripleDES_ECB(_base.BlockCipherECB, TripleDES):
    pass


class TripleDES_CBC(_base.BlockCipherCBC, TripleDES):
    pass


class TripleDES_CFB(_base.BlockCipherCFB, TripleDES):
    pass


class TripleDES_OFB(_base.BlockCipherOFB, TripleDES):
    pass
