import abc
import os

__all__ = ['Padding', 'PKCS7', 'ANSIX923', 'ISO10126']

# ==============
# Common Padding
# ==============


class _CommonPadder(object):
    def __init__(self, block_size):
        self.block_size = block_size
        self._size = 0

    def update(self, data):
        self._size += len(data)
        return data

    def finalize(self):
        padded_size = self.block_size - (self._size % self.block_size)
        return self._padding(padded_size)

    @staticmethod
    def _padding(padded_size):
        raise NotImplementedError


class _CommonUnpadder(object):
    def __init__(self, block_size):
        self.block_size = block_size
        self._buf = b''

    def update(self, data):
        self._buf += data
        remaining_size = (len(self._buf) % self.block_size) or self.block_size
        result = self._buf[:-remaining_size]
        self._buf = self._buf[-remaining_size:]
        return result

    def finalize(self):
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
        self.block_size = block_size

    def padder(self):
        return self._padder_cls(self.block_size)

    def unpadder(self):
        return self._unpadder_cls(self.block_size)


# ==============
# PKCS#7 Padding
# ==============


class PKCS7Padder(_CommonPadder):
    @staticmethod
    def _padding(padded_size):
        return padded_size.to_bytes(1, 'big') * padded_size


class PKCS7Unpadder(_CommonUnpadder):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != padded_size:
                raise ValueError('invalid padding')


class PKCS7(Padding):
    _padder_cls = PKCS7Padder
    _unpadder_cls = PKCS7Unpadder


# ==================
# ANSI X9.23 Padding
# ==================


class ANSIX923Padder(_CommonPadder):
    @staticmethod
    def _padding(padded_size):
        return b'\x00' * (padded_size - 1) + padded_size.to_bytes(1, 'big')


class ANSIX923Unpadder(_CommonUnpadder):
    @staticmethod
    def _check(buffer, padded_size):
        for i in range(2, padded_size + 1):
            if buffer[-i] != 0:
                raise ValueError('invalid padding')


class ANSIX923(Padding):
    _padder_cls = ANSIX923Padder
    _unpadder_cls = ANSIX923Unpadder


# =================
# ISO 10126 Padding
# =================


class ISO10126Padder(_CommonPadder):
    @staticmethod
    def _padding(padded_size):
        return os.urandom(padded_size - 1) + padded_size.to_bytes(1, 'big')


class ISO10126Unpadder(_CommonUnpadder):
    @staticmethod
    def _check(buffer, padded_size):
        pass


class ISO10126(Padding):
    _padder_cls = ISO10126Padder
    _unpadder_cls = ISO10126Unpadder
