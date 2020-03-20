from . import _base, _lib, _utils

_TripleDES_ATTRS = {
    '_algorithm': _lib.TripleDES,
    'name': 'TripleDES',
    'block_size': 8,
    'key_sizes': frozenset([8, 16, 24])
}

_X = _utils._make_X(_TripleDES_ATTRS)


class TripleDES(_X(_base.BlockCipher)):
    pass


class TripleDES_ECB(_X(_base.BlockCipherECB)):
    pass


class TripleDES_CBC(_X(_base.BlockCipherCBC)):
    pass


class TripleDES_CFB(_X(_base.BlockCipherCFB)):
    pass


class TripleDES_OFB(_X(_base.BlockCipherOFB)):
    pass


class TripleDES_CTR(_X(_base.BlockCipherCTR)):
    pass
