import inspect

from cryptography.hazmat.backends import default_backend                # NOQA; isort:skip
from cryptography.hazmat.primitives.ciphers import Cipher               # NOQA; isort:skip
from cryptography.hazmat.primitives.ciphers.algorithms import (         # NOQA; isort:skip
    ARC4, ChaCha20,
    AES, Blowfish, Camellia, CAST5, IDEA, SEED, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (              # NOQA; isort:skip
    ECB, CBC, CFB, OFB, CTR,
    Mode, ModeWithInitializationVector, ModeWithNonce
)

backend = default_backend()

_MODE_REGISTRY = {
    'ECB': ECB,
    'CBC': CBC,
    'CFB': CFB,
    'OFB': OFB,
    'CTR': CTR
}


def lookup_mode(mode):
    if inspect.isclass(mode) and issubclass(mode, Mode):
        return mode

    if isinstance(mode, str):
        try:
            return _MODE_REGISTRY[mode.upper()]
        except KeyError:
            pass

    raise ValueError(
        'mode must be in {}, got {}'.format(set(_MODE_REGISTRY), mode)
    )


def create_mode(mode, **kwargs):
    mode = lookup_mode(mode)

    args = {}
    if issubclass(mode, ModeWithInitializationVector):
        try:
            args['initialization_vector'] = kwargs['iv']
        except KeyError:
            raise TypeError('missing required keyword-only argument: "iv"')
    if issubclass(mode, ModeWithNonce):
        try:
            args['nonce'] = kwargs['nonce']
        except KeyError:
            raise TypeError('missing required keyword-only argument: "nonce"')

    return mode(**args)
