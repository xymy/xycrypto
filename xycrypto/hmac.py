import functools
import os
from hmac import compare_digest

__all__ = ['HMAC', 'compare_digest']

_CHUNK_SIZE = 0x100000
_TRANS_36 = bytes((x ^ 0x36) for x in range(256))
_TRANS_5C = bytes((x ^ 0x5C) for x in range(256))


class HMAC(object):
    """Hash-based message authentication codes."""

    # ==================
    # Context Interfaces
    # ==================

    def __init__(self, hash_cls, key):
        """Initialize the current context."""

        self._i_ctx = hash_cls()
        self._o_ctx = hash_cls()
        self.block_size = self._o_ctx.block_size
        self.digest_size = self._o_ctx.digest_size

        if len(key) > self.block_size:
            ctx = hash_cls()
            ctx.update(key)
            key = ctx.finalize()
        key = key.ljust(self.block_size, b'\0')

        self._i_ctx.update(key.translate(_TRANS_36))
        self._o_ctx.update(key.translate(_TRANS_5C))

    def update(self, data):
        """Update the current context."""

        self._i_ctx.update(data)

    def finalize(self):
        """Finalize the current context and return the message digest as bytes."""

        ctx = self._o_ctx.copy()
        ctx.update(self._i_ctx.finalize())
        return ctx.finalize()

    def verify(self, signature):
        """Finalize the current context and securely compare digest to signature."""

        return compare_digest(self.finalize(), signature)

    def copy(self):
        """Copy the current context."""

        other = type(self).__new__(type(self))
        other._i_ctx = self._i_ctx.copy()
        other._o_ctx = self._o_ctx.copy()
        other.block_size = self.block_size
        other.digest_size = self.digest_size
        return other

    # ===============
    # Fast Interfaces
    # ===============

    @classmethod
    def hash(cls, hash_cls, key, data, **kwargs):
        """Return hash of data from byte string or unicode string."""

        if isinstance(data, str):
            data = data.encode('utf-8')
        ctx = cls(hash_cls, key, **kwargs)
        ctx.update(data)
        return ctx.finalize()

    @classmethod
    def hash_iter(cls, hash_cls, key, iterable, **kwargs):
        """Return hash of data from iterable of bytes."""

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
        """Return hash of data from file."""

        with open(filepath, 'rb') as f:
            return cls.hash_fileobj(hash_cls, key, f, **kwargs)

    @classmethod
    def hash_dir(cls, hash_cls, key, dirpath, **kwargs):
        """Return hash of data from directory."""

        digest_size = getattr(cls(hash_cls, key, **kwargs), 'digest_size')

        def _hash_dir(cls, hash_cls, key, dirpath, **kwargs):
            result = b'\x00' * digest_size
            with os.scandir(dirpath) as it:
                for entry in it:
                    if entry.is_dir():
                        value = cls.hash_dir(hash_cls, key, entry, **kwargs)
                    else:
                        value = cls.hash_file(hash_cls, key, entry, **kwargs)
                    result = bytes(x ^ y for x, y in zip(result, value))
            return result

        return _hash_dir(cls, hash_cls, key, dirpath, **kwargs)

    @classmethod
    def hash_fs(cls, hash_cls, key, path, **kwargs):
        """Return hash of data from filesystems."""

        if os.path.isdir(path):
            return cls.hash_dir(hash_cls, key, path, **kwargs)
        return cls.hash_file(hash_cls, key, path, **kwargs)
