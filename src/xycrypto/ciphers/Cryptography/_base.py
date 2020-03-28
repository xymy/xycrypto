import abc

from xycrypto.ciphers import base, utils

from . import _lib


@base.Cipher.register
class Cipher(metaclass=abc.ABCMeta):
    """Abstract base class for cipher."""

    @property
    @abc.abstractmethod
    def _algorithm(self):
        """The algorithm of cipher."""

    @property
    @abc.abstractmethod
    def name(self):
        """The name of cipher."""

    @abc.abstractmethod
    def encryptor(self):
        """Return the encryptor context."""

    @abc.abstractmethod
    def decryptor(self):
        """Return the decryptor context."""

    def encrypt(self, data):
        """Encrypt data and return encrypted data."""

        encryptor = self.encryptor()
        temp = encryptor.update(data)
        return temp + encryptor.finalize()

    def decrypt(self, data):
        """Decrypt data and return decrypted data."""

        decryptor = self.decryptor()
        temp = decryptor.update(data)
        return temp + decryptor.finalize()


@base.StreamCipher.register
class StreamCipher(Cipher):
    """Abstract base class for stream cipher."""

    def __init__(self, key):
        self._cipher = _lib.Cipher(self._algorithm(key), None, _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()


@base.BlockCipher.register
class BlockCipher(Cipher):
    """Abstract base class for block cipher."""

    @property
    @abc.abstractmethod
    def block_size(self):
        """The block size in bytes of cipher."""

    @property
    def mode_name(self):
        """The mode name of cipher."""

        return self._cipher.mode.name

    def __init__(self, key, mode, **kwargs):
        mode = _lib.create_mode(mode, **kwargs)

        # For ECB and CBC modes, the default padding is PKCS7.
        # For other modes, padding will not be added automatically.
        # However, user can force padding by providing the padding argument.
        if mode.name in {'ECB', 'CBC'}:
            padding = kwargs.pop('padding', 'PKCS7')
        else:
            padding = kwargs.pop('padding', None)

        self._cipher = _lib.Cipher(self._algorithm(key), mode, _lib.backend)
        self._padding = utils.determine_padding(padding, self.block_size)

    def encryptor(self):
        return utils.determine_encryptor(self._cipher, self._padding)

    def decryptor(self):
        return utils.determine_decryptor(self._cipher, self._padding)


@base.BlockCipherWithMode.register
class BlockCipherWithMode(BlockCipher):
    """Abstract base class for block cipher with mode."""


@base.BlockCipherECB.register
class BlockCipherECB(BlockCipherWithMode):
    """Abstract base class for block cipher in ECB mode."""

    mode_name = 'ECB'

    def __init__(self, key, *, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.ECB(), _lib.backend)
        self._padding = utils.determine_padding(padding, self.block_size)


@base.BlockCipherCBC.register
class BlockCipherCBC(BlockCipherWithMode):
    """Abstract base class for block cipher in CBC mode."""

    mode_name = 'CBC'

    def __init__(self, key, *, iv, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CBC(iv), _lib.backend)
        self._padding = utils.determine_padding(padding, self.block_size)


@base.BlockCipherCFB.register
class BlockCipherCFB(BlockCipherWithMode):
    """Abstract base class for block cipher in CFB mode."""

    mode_name = 'CFB'

    def __init__(self, key, *, iv, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CFB(iv), _lib.backend)
        self._padding = utils.determine_padding(padding, self.block_size)


@base.BlockCipherOFB.register
class BlockCipherOFB(BlockCipherWithMode):
    """Abstract base class for block cipher in OFB mode."""

    mode_name = 'OFB'

    def __init__(self, key, *, iv, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.OFB(iv), _lib.backend)
        self._padding = utils.determine_padding(padding, self.block_size)


@base.BlockCipherCTR.register
class BlockCipherCTR(BlockCipherWithMode):
    """Abstract base class for block cipher in CTR mode."""

    mode_name = 'CTR'

    def __init__(self, key, *, nonce, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CTR(nonce), _lib.backend)
        self._padding = utils.determine_padding(padding, self.block_size)
