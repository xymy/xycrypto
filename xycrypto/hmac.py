import functools
import hmac
import itertools
import os

__all__ = ['HMAC']

_CHUNK_SIZE = 0x100000
_TRANS_36 = bytes((x ^ 0x36) for x in range(256))
_TRANS_5C = bytes((x ^ 0x5C) for x in range(256))


class HMAC(object):
    """Hash-based message authentication codes."""

    # =================
    # Context Interface
    # =================

    def __init__(self, hash_cls, key):
        """Initialize the current context."""

        self.i_ctx = hash_cls()
        self.o_ctx = hash_cls()
        self.block_size = self.o_ctx.block_size
        self.digest_size = self.o_ctx.digest_size

        if len(key) > self.block_size:
            ctx = hash_cls()
            ctx.update(key)
            key = ctx.finalize()
        key = key.ljust(self.block_size, b'\0')

        self.i_ctx.update(key.translate(_TRANS_36))
        self.o_ctx.update(key.translate(_TRANS_5C))

    def update(self, data):
        """Update the current context."""

        self.i_ctx.update(data)

    def finalize(self):
        """Finalize the current context and return the message digest as bytes."""

        ctx = self.o_ctx.copy()
        ctx.update(self.i_ctx.finalize())
        return ctx.finalize()

    def verify(self, signature):
        """Finalize the current context and securely compare digest to signature."""

        return hmac.compare_digest(self.finalize(), signature)

    def copy(self):
        """Copy the current context."""

        other = type(self).__new__(type(self))
        other.block_size = self.block_size
        other.digest_size = self.digest_size
        other.i_ctx = self.i_ctx.copy()
        other.o_ctx = self.o_ctx.copy()
        return other

    # ==============
    # Fast Interface
    # ==============

    @classmethod
    def hash(cls, hash_cls, key, data, **kwargs):
        """Return hash of data from memory."""

        ctx = cls(hash_cls, key, **kwargs)
        if isinstance(data, str):
            data = data.encode('utf-8')
        ctx.update(data)
        return ctx.finalize()

    @classmethod
    def hash_iter(cls, hash_cls, key, iterable, **kwargs):
        ctx = cls(hash_cls, key, **kwargs)
        for chunk in iterable:
            ctx.update(chunk)
        return ctx.finalize()

    @classmethod
    def hash_fileobj(cls, hash_cls, key, fileobj, **kwargs):
        """Return hash of data from file object."""

        it = iter(functools.partial(fileobj.read, _CHUNK_SIZE), b'')
        return cls.hash_iter(hash_cls, key, it, **kwargs)

    @classmethod
    def hash_file(cls, hash_cls, key, filepath, **kwargs):
        """Return hash of data from a file."""

        with open(filepath, 'rb') as f:
            return cls.hash_fileobj(hash_cls, key, f, **kwargs)

    @classmethod
    def hash_dir(cls, hash_cls, key, dirpath, **kwargs):
        """Return hash of data from a directory."""

        with os.scandir(dirpath) as it:
            result = itertools.repeat(0)
            for entry in it:
                if entry.is_dir():
                    value = cls.hash_dir(hash_cls, key, entry, **kwargs)
                else:
                    value = cls.hash_file(hash_cls, key, entry, **kwargs)
                result = bytes(x ^ y for x, y in zip(result, value))
            if not isinstance(result, bytes):
                raise RuntimeError('empty directory')
            return result

    @classmethod
    def hash_fs(cls, hash_cls, key, path, **kwargs):
        """Return hash of data from a filesystem."""

        if os.path.isdir(path):
            return cls.hash_dir(hash_cls, key, path, **kwargs)
        return cls.hash_file(hash_cls, key, path, **kwargs)
