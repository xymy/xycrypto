import abc

from . import _lib, _utils


class Cipher(metaclass=abc.ABCMeta):
    """Abstract base class for cipher."""

    @property
    @abc.abstractmethod
    def _algorithm(self):
        """The algorithm of cipher."""

    @property
    def key_size(self):
        """The key size in bytes of cipher."""

        return self._cipher.algorithm.key_size // 8

    @abc.abstractmethod
    def __init__(self, algorithm, mode):
        """Prepare the cipher context."""

        self._cipher = _lib.Cipher(algorithm, mode, _lib.backend)

    @abc.abstractmethod
    def encryptor(self):
        """Return the encryptor context."""

    @abc.abstractmethod
    def decryptor(self):
        """Return the decryptor context."""

    def encrypt(self, data):
        """Encrypt data and return."""

        encryptor = self.encryptor()
        temp = encryptor.update(data)
        return temp + encryptor.finalize()

    def decrypt(self, data):
        """Decrypt data and return."""

        decryptor = self.decryptor()
        temp = decryptor.update(data)
        return temp + decryptor.finalize()


class StreamCipher(Cipher):
    """Abstract base class for stream cipher."""

    def __init__(self, key):
        self._cipher = _lib.Cipher(self._algorithm(key), None, _lib.backend)

    def encryptor(self):
        return self._cipher.encryptor()

    def decryptor(self):
        return self._cipher.decryptor()


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
        mode, padding = _utils._setup_mode_padding(mode, **kwargs)
        self._cipher = _lib.Cipher(self._algorithm(key), mode, _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)

    def encryptor(self):
        return _utils._determine_encryptor(self._cipher, self._padding)

    def decryptor(self):
        return _utils._determine_decryptor(self._cipher, self._padding)


class BlockCipherECB(BlockCipher):
    """Abstract base class for block cipher in ECB mode."""

    mode_name = 'ECB'

    def __init__(self, key, *, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.ECB(), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)


class BlockCipherCBC(BlockCipher):
    """Abstract base class for block cipher in CBC mode."""

    mode_name = 'CBC'

    def __init__(self, key, *, iv, padding='PKCS7'):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CBC(iv), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)


@StreamCipher.register
class BlockCipherCFB(BlockCipher):
    """Abstract base class for block cipher in CFB mode."""

    mode_name = 'CFB'

    def __init__(self, key, *, iv, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CFB(iv), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)


@StreamCipher.register
class BlockCipherOFB(BlockCipher):
    """Abstract base class for block cipher in OFB mode."""

    mode_name = 'OFB'

    def __init__(self, key, *, iv, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.OFB(iv), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)


@StreamCipher.register
class BlockCipherCTR(BlockCipher):
    """Abstract base class for block cipher in CTR mode."""

    mode_name = 'CTR'

    def __init__(self, key, *, nonce, padding=None):
        self._cipher = _lib.Cipher(self._algorithm(key), _lib.CTR(nonce), _lib.backend)
        self._padding = _utils._determine_padding(padding, self.block_size)
