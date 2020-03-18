import abc
import os

__all__ = ['PKCS7', 'ANSIX923', 'ISO10126']


class _CommonPadder(object):
    def __init__(self, block_size):
        """Initialize the current context."""

        self.block_size = block_size
        self._size = 0

    def update(self, data):
        """Update the current context."""

        self._size += len(data)
        return data

    def finalize(self):
        """Finalize the current context and return the rest of the data."""

        padded_size = self.block_size - (self._size % self.block_size)
        return self._pad(padded_size)

    @staticmethod
    def _pad(padded_size):
        raise NotImplementedError


class _CommonUnpadder(object):
    def __init__(self, block_size):
        """Initialize the current context."""

        self.block_size = block_size
        self._buf = b''

    def update(self, data):
        """Update the current context."""

        self._buf += data
        remaining_size = (len(self._buf) % self.block_size) or self.block_size
        result = self._buf[:-remaining_size]
        self._buf = self._buf[-remaining_size:]
        return result

    def finalize(self):
        """Finalize the current context and return the rest of the data."""

        if len(self._buf) != self.block_size:
            raise ValueError('invalid padding')
        padded_size = self._buf[-1]
        if padded_size > self.block_size:
            raise ValueError('invalid padding')
        self._check(self._buf, padded_size)
        return self._buf[:-padded_size]

    @staticmethod
    def _check(buffer, padded_size):
        raise NotImplementedError


class Padding(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def _padder_cls(self):
        """The class of padder context."""

    @property
    @abc.abstractmethod
    def _unpadder_cls(self):
        """The class of unpadder context."""

    def __init__(self, block_size):
        """Prepare the context."""

        if not isinstance(block_size, int):
            raise TypeError('block_size must be int, got {}'.format(type(block_size).__name__))
        if block_size < 1 or block_size > 255:
            raise ValueError('block_size must be in [1, 255], got {}'.format(block_size))

        self.block_size = block_size

    def padder(self):
        """Return the padder context."""

        return self._padder_cls(self.block_size)

    def unpadder(self):
        """Return the unpadder context."""

        return self._unpadder_cls(self.block_size)

    class _PaddingWrapper(object):
        def __init__(self, padded_ctx, padding_ctx):
            self.padded_ctx = padded_ctx
            self.padding_ctx = padding_ctx

        def update(self, data):
            return self.padded_ctx.update(self.padding_ctx.update(data))

        def finalize(self):
            temp = self.padded_ctx.update(self.padding_ctx.finalize())
            return temp + self.padded_ctx.finalize()

    def wrap_encryptor(self, encryptor_ctx):
        return self._PaddingWrapper(encryptor_ctx, self.padder())

    def wrap_decryptor(self, decryptor_ctx):
        return self._PaddingWrapper(self.unpadder(), decryptor_ctx)


# ==============
# PKCS#7 Padding
# ==============


class _PKCS7Padder(_CommonPadder):
    @staticmethod
    def _pad(padded_size):
        return padded_size.to_bytes(1, 'big') * padded_size


class _PKCS7Unpadder(_CommonUnpadder):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != padded_size:
                raise ValueError('invalid padding')


class PKCS7(Padding):
    _padder_cls = _PKCS7Padder
    _unpadder_cls = _PKCS7Unpadder


# ==================
# ANSI X9.23 Padding
# ==================


class _ANSIX923Padder(_CommonPadder):
    @staticmethod
    def _pad(padded_size):
        return b'\x00' * (padded_size - 1) + padded_size.to_bytes(1, 'big')


class _ANSIX923Unpadder(_CommonUnpadder):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != 0:
                raise ValueError('invalid padding')


class ANSIX923(Padding):
    _padder_cls = _ANSIX923Padder
    _unpadder_cls = _ANSIX923Unpadder


# =================
# ISO 10126 Padding
# =================


class _ISO10126Padder(_CommonPadder):
    @staticmethod
    def _pad(padded_size):
        return os.urandom(padded_size - 1) + padded_size.to_bytes(1, 'big')


class _ISO10126Unpadder(_CommonUnpadder):
    @staticmethod
    def _check(buffer, padded_size):
        pass    # no need to check


class ISO10126(Padding):
    _padder_cls = _ISO10126Padder
    _unpadder_cls = _ISO10126Unpadder


# ==============
# Lookup Padding
# ==============


_PADDING_TABLE = {
    'PKCS7': PKCS7,
    'ANSIX923': ANSIX923,
    'ISO10126': ISO10126
}


def _lookup_padding(padding):
    if isinstance(padding, str):
        padding = _PADDING_TABLE.get(padding.upper(), None)
        if padding is not None:
            return padding
    elif isinstance(padding, Padding):
        return padding
    raise ValueError('padding must be in {}'.format(set(_PADDING_TABLE.keys())))