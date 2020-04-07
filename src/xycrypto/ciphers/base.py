import abc


class Cipher(metaclass=abc.ABCMeta):
    """Abstract base class for cipher."""

    @abc.abstractmethod
    def encryptor(self):
        """Return the encryptor context."""

    @abc.abstractmethod
    def decryptor(self):
        """Return the decryptor context."""

    @abc.abstractmethod
    def encrypt(self, data):
        """Encrypt data and return encrypted data."""

    @abc.abstractmethod
    def decrypt(self, data):
        """Decrypt data and return decrypted data."""


class StreamCipher(Cipher):
    """Abstract base class for stream cipher."""


class BlockCipher(Cipher):
    """Abstract base class for block cipher."""


class BlockCipherECB(BlockCipher):
    """Abstract base class for block cipher in ECB mode."""


class BlockCipherCBC(BlockCipher):
    """Abstract base class for block cipher in CBC mode."""


class BlockCipherCFB(BlockCipher):
    """Abstract base class for block cipher in CFB mode."""


class BlockCipherOFB(BlockCipher):
    """Abstract base class for block cipher in OFB mode."""


class BlockCipherCTR(BlockCipher):
    """Abstract base class for block cipher in CTR mode."""
