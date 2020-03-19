from . import _base, _lib, _utils

_TripleDES_ATTRS = {
    '_algorithm': _lib.TripleDES,
    'name': 'TripleDES',
    'block_size': 8
}

_X = _utils._make_X(_TripleDES_ATTRS)


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
