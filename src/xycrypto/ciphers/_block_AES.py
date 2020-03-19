from . import _base, _lib, _utils

_AES_ATTRS = {
    '_algorithm': _lib.AES,
    'name': 'AES',
    'block_size': 16
}

_X = _utils._make_X(_AES_ATTRS)


class AES_ECB(_X(_base.BlockCipherECB)):
    pass


class AES_CBC(_X(_base.BlockCipherCBC)):
    pass


class AES_CFB(_X(_base.BlockCipherCFB)):
    pass


class AES_OFB(_X(_base.BlockCipherOFB)):
    pass


class AES_CTR(_X(_base.BlockCipherCTR)):
    pass
