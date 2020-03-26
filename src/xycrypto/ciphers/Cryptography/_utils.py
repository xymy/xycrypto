import inspect

from xycrypto.padding import _create_padding

from . import _lib

_MODE_TABLE = {
    'ECB': _lib.ECB,
    'CBC': _lib.CBC,
    'CFB': _lib.CFB,
    'OFB': _lib.OFB,
    'CTR': _lib.CTR
}


def _lookup_mode(mode):
    if inspect.isclass(mode) and issubclass(mode, _lib.Mode):
        return mode
    if isinstance(mode, str):
        try:
            return _MODE_TABLE[mode.upper()]
        except KeyError:
            pass
    raise ValueError('mode must be in {}'.format(set(_MODE_TABLE)))


def _setup_mode_padding(mode, **kwargs):
    mode = _lookup_mode(mode)

    args = {}
    if issubclass(mode, _lib.ModeWithInitializationVector):
        try:
            args['initialization_vector'] = kwargs['iv']
        except KeyError:
            raise TypeError('missing required keyword-only argument: "iv"')
    if issubclass(mode, _lib.ModeWithNonce):
        try:
            args['nonce'] = kwargs['nonce']
        except KeyError:
            raise TypeError('missing required keyword-only argument: "nonce"')

    # For ECB and CBC modes, the default padding is PKCS7.
    # For other modes, padding will not be added automatically.
    # However, user can force padding by providing the padding argument.
    if mode.name in {'ECB', 'CBC'}:
        padding = kwargs.pop('padding', 'PKCS7')
    else:
        padding = kwargs.pop('padding', None)

    return mode(**args), padding


def _determine_padding(padding, block_size):
    if padding is None:
        return None
    return _create_padding(padding, block_size)


class _PaddingWrapper(object):
    def __init__(self, padded_ctx, padding_ctx):
        self.padded_ctx = padded_ctx
        self.padding_ctx = padding_ctx

    def update(self, data):
        return self.padded_ctx.update(self.padding_ctx.update(data))

    def finalize(self):
        temp = self.padded_ctx.update(self.padding_ctx.finalize())
        return temp + self.padded_ctx.finalize()


def _determine_encryptor(cipher, padding):
    encryptor = cipher.encryptor()
    if padding is None:
        return encryptor
    return _PaddingWrapper(encryptor, padding.padder())


def _determine_decryptor(cipher, padding):
    decryptor = cipher.decryptor()
    if padding is None:
        return decryptor
    return _PaddingWrapper(padding.unpadder(), decryptor)


def _make_X(cipher_attrs):
    def _X(cipher_base):
        name = cipher_base.__name__ + '_' + cipher_attrs['name']
        return type(name, (cipher_base,), cipher_attrs)
    return _X
