import abc
import inspect
import os

__all__ = ['DUMMY', 'PKCS7', 'ANSIX923', 'ISO10126']


# ============================================================================ #
#                                  Interfaces                                  #
# ============================================================================ #


class Padding(metaclass=abc.ABCMeta):
    """Abstract base class for padding."""

    @abc.abstractmethod
    def padder(self):
        """Return the padder context."""

    @abc.abstractmethod
    def unpadder(self):
        """Return the unpadder context."""

    @abc.abstractmethod
    def pad(self, data):
        """Pad data and return padded data."""

    @abc.abstractmethod
    def unpad(self, data):
        """Unpad data and return unpadded data."""


class PaddingContext(metaclass=abc.ABCMeta):
    """Abstract base class for padding context."""

    @abc.abstractmethod
    def update(self, data):
        """Update the current context and return the available data."""

    @abc.abstractmethod
    def finalize(self):
        """Finalize the current context and return the rest of the data."""


class Padder(PaddingContext):
    """Abstract base class for padder context."""


class Unpadder(PaddingContext):
    """Abstract base class for unpadder context."""


# ============================================================================ #
#                                  Frameworks                                  #
# ============================================================================ #


class _PaddingFramework(Padding):
    def __init__(self, block_size):
        if not isinstance(block_size, int):
            raise TypeError(
                'block_size must be int, got {}'.format(type(block_size).__name__)
            )

        if block_size < 1 or block_size > 255:
            raise ValueError(
                'block_size must be in [1, 255], got {}'.format(block_size)
            )

        self.block_size = block_size

    def pad(self, data):
        padder = self.padder()
        temp = padder.update(data)
        return temp + padder.finalize()

    def unpad(self, data):
        unpadder = self.unpadder()
        temp = unpadder.update(data)
        return temp + unpadder.finalize()


class _PadderFramework(Padder):
    def __init__(self, block_size):
        self.block_size = block_size
        self._size = 0

    def update(self, data):
        self._size += len(data)
        return data

    def finalize(self):
        block_size = self.block_size
        padded_size = block_size - (self._size % block_size)
        return self._pad(padded_size)

    @staticmethod
    @abc.abstractmethod
    def _pad(padded_size):
        """Return the padding."""


class _UnpadderFramework(Unpadder):
    def __init__(self, block_size):
        self.block_size = block_size
        self._buffer = b''

    def update(self, data):
        if not data:    # no effect for empty data
            return b''

        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError('require len(data) % {0} == 0'.format(block_size))

        result = self._buffer
        self._buffer = data
        return result

    def finalize(self):
        block_size = self.block_size
        if len(self._buffer) < block_size:
            raise ValueError('incomplete padding')

        padded_size = self._buffer[-1]
        if padded_size > block_size:
            raise ValueError('invalid padding')
        self._check(self._buffer, padded_size)
        return self._buffer[:-padded_size]

    @staticmethod
    @abc.abstractmethod
    def _check(buffer, padded_size):
        """Check the padding."""


# ============================================================================ #
#                               Implementations                                #
# ============================================================================ #


# 0. DUMMY


class DUMMY(Padding):
    def __init__(self, block_size):
        pass

    def padder(self):
        return DUMMYPadder(0)

    def unpadder(self):
        return DUMMYUnpadder(0)

    def pad(self, data):
        return data

    def unpad(self, data):
        return data


class DUMMYPadder(Padder):
    def __init__(self, block_size):
        pass

    def update(self, data):
        return data

    def finalize(self):
        return b''


class DUMMYUnpadder(Unpadder):
    def __init__(self, block_size):
        pass

    def update(self, data):
        return data

    def finalize(self):
        return b''


# 1. PKCS#7


class PKCS7(_PaddingFramework):
    def padder(self):
        return PKCS7Padder(self.block_size)

    def unpadder(self):
        return PKCS7Unpadder(self.block_size)


class PKCS7Padder(_PadderFramework):
    @staticmethod
    def _pad(padded_size):
        return padded_size.to_bytes(1, 'big') * padded_size


class PKCS7Unpadder(_UnpadderFramework):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != padded_size:
                raise ValueError('invalid padding')


# 2. ANSI X9.23


class ANSIX923(_PaddingFramework):
    def padder(self):
        return ANSIX923Padder(self.block_size)

    def unpadder(self):
        return ANSIX923Unpadder(self.block_size)


class ANSIX923Padder(_PadderFramework):
    @staticmethod
    def _pad(padded_size):
        return b'\x00' * (padded_size - 1) + padded_size.to_bytes(1, 'big')


class ANSIX923Unpadder(_UnpadderFramework):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != 0:
                raise ValueError('invalid padding')


# 3. ISO 10126


class ISO10126(_PaddingFramework):
    def padder(self):
        return ISO10126Padder(self.block_size)

    def unpadder(self):
        return ISO10126Unpadder(self.block_size)


class ISO10126Padder(_PadderFramework):
    @staticmethod
    def _pad(padded_size):
        return os.urandom(padded_size - 1) + padded_size.to_bytes(1, 'big')


class ISO10126Unpadder(_UnpadderFramework):
    @staticmethod
    def _check(buffer, padded_size):
        pass    # no need to check


# ============================================================================ #
#                                  Utilities                                   #
# ============================================================================ #


_PADDING_TABLE = {
    'DUMMY': DUMMY,
    'PKCS7': PKCS7,
    'ANSIX923': ANSIX923,
    'ISO10126': ISO10126,
    'D': DUMMY,
    'P': PKCS7,
    'A': ANSIX923,
    'I': ISO10126
}


def _lookup_padding(padding):
    if inspect.isclass(padding) and issubclass(padding, Padding):
        return padding

    if isinstance(padding, str):
        try:
            return _PADDING_TABLE[padding.upper()]
        except KeyError:
            pass

    raise ValueError(
        'padding must be in {}, got {}'.format(set(_PADDING_TABLE), padding)
    )


def _create_padding(padding, block_size):
    padding = _lookup_padding(padding)
    return padding(block_size)


def _register_padding(padding_name, padding_class):
    _PADDING_TABLE[padding_name.upper()] = padding_class


def _unregister_padding(padding_name):
    del _PADDING_TABLE[padding_name.upper()]
