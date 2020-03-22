import abc
import inspect
import os

__all__ = ['PKCS7', 'ANSIX923', 'ISO10126']


class PadderContext(metaclass=abc.ABCMeta):
    """Abstract base class for padder context."""

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
    @abc.abstractmethod
    def _pad(padded_size):
        """Return the padding."""


class UnpadderContext(metaclass=abc.ABCMeta):
    """Abstract base class for unpadder context."""

    def __init__(self, block_size):
        """Initialize the current context."""

        self.block_size = block_size
        self._buf = b''

    def update(self, data):
        """Update the current context."""

        self._buf += data
        buffered_size = (len(self._buf) % self.block_size) or self.block_size
        result = self._buf[:-buffered_size]
        self._buf = self._buf[-buffered_size:]
        return result

    def finalize(self):
        """Finalize the current context and return the rest of the data."""

        if len(self._buf) != self.block_size:
            raise ValueError('incomplete padding')

        padded_size = self._buf[-1]
        if padded_size > self.block_size:
            raise ValueError('invalid padding')
        self._check(self._buf, padded_size)
        return self._buf[:-padded_size]

    @staticmethod
    @abc.abstractmethod
    def _check(buffer, padded_size):
        """Check the padding."""


class FastUnpadderContext(UnpadderContext):
    """Abstract base class for fast unpadder context."""

    def __init__(self, block_size, total_size):
        """Initialize the current context."""

        self.block_size = block_size
        self._size = total_size
        self._buf = b''

    def update(self, data):
        """Update the current context."""

        remaining_size = self._size - len(data)
        if remaining_size < 0:
            raise ValueError('too much data')
        self._size = remaining_size

        buffered_size = self.block_size - remaining_size
        if buffered_size > 0:
            self._buf += data[-buffered_size:]
            return data[:-buffered_size]
        else:
            return data

    def finalize(self):
        """Finalize the current context and return the rest of the data."""

        return super().finalize()


class Padding(metaclass=abc.ABCMeta):
    """Abstract base class for padding."""

    @property
    @abc.abstractmethod
    def _padder_cls(self):
        """The class of padder context."""

    @property
    @abc.abstractmethod
    def _unpadder_cls(self):
        """The class of unpadder context."""

    @property
    @abc.abstractmethod
    def _fast_unpadder_cls(self):
        """The class of fast unpadder context."""

    def __init__(self, block_size):
        """Prepare the padding context."""

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

    def fast_unpadder(self, total_size):
        """Return the fast unpadder context."""

        return self._fast_unpadder_cls(self.block_size, total_size)

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


class _PKCS7Padder(PadderContext):
    @staticmethod
    def _pad(padded_size):
        return padded_size.to_bytes(1, 'big') * padded_size


class _PKCS7Unpadder(UnpadderContext):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != padded_size:
                raise ValueError('invalid padding')


class _PKCS7FastUnpadder(FastUnpadderContext):
    _check = _PKCS7Unpadder._check


class PKCS7(Padding):
    _padder_cls = _PKCS7Padder
    _unpadder_cls = _PKCS7Unpadder
    _fast_unpadder_cls = _PKCS7FastUnpadder


# ==================
# ANSI X9.23 Padding
# ==================


class _ANSIX923Padder(PadderContext):
    @staticmethod
    def _pad(padded_size):
        return b'\x00' * (padded_size - 1) + padded_size.to_bytes(1, 'big')


class _ANSIX923Unpadder(UnpadderContext):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != 0:
                raise ValueError('invalid padding')


class _ANSIX923FastUnpadder(FastUnpadderContext):
    _check = _ANSIX923Unpadder._check


class ANSIX923(Padding):
    _padder_cls = _ANSIX923Padder
    _unpadder_cls = _ANSIX923Unpadder
    _fast_unpadder_cls = _ANSIX923FastUnpadder


# =================
# ISO 10126 Padding
# =================


class _ISO10126Padder(PadderContext):
    @staticmethod
    def _pad(padded_size):
        return os.urandom(padded_size - 1) + padded_size.to_bytes(1, 'big')


class _ISO10126Unpadder(UnpadderContext):
    @staticmethod
    def _check(buffer, padded_size):
        pass    # no need to check


class _ISO10126FastUnpadder(FastUnpadderContext):
    _check = _ISO10126Unpadder._check


class ISO10126(Padding):
    _padder_cls = _ISO10126Padder
    _unpadder_cls = _ISO10126Unpadder
    _fast_unpadder_cls = _ISO10126FastUnpadder


# ==============
# Lookup Padding
# ==============


_PADDING_TABLE = {
    'PKCS7': PKCS7,
    'ANSIX923': ANSIX923,
    'ISO10126': ISO10126
}


def _lookup_padding(padding):
    if inspect.isclass(padding) and issubclass(padding, Padding):
        return padding
    if isinstance(padding, str):
        try:
            return _PADDING_TABLE[padding.upper()]
        except KeyError:
            pass
    raise ValueError('padding must be in {}'.format(set(_PADDING_TABLE)))
