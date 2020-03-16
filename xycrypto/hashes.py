import abc
import functools
import hashlib
import os

__all__ = [
    'MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512',
    'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512', 'SHAKE128', 'SHAKE256',
    'BLAKE2b', 'BLAKE2s'
]

_CHUNK_SIZE = 0x100000


class Hash(metaclass=abc.ABCMeta):
    """Abstract base class for hash context."""

    @property
    @abc.abstractmethod
    def _cls(self):
        """The class of hash context."""

    # ==================
    # Context Interfaces
    # ==================

    def __init__(self):
        """Initialize the current context."""

        self._ctx = self._cls()

    def update(self, data):
        """Update the current context."""

        self._ctx.update(data)

    def finalize(self):
        """Finalize the current context and return the message digest as bytes."""

        return self._ctx.digest()   # note the interface of stdlib

    def copy(self):
        """Copy the current context."""

        return self._ctx.copy()

    # ===============
    # Fast Interfaces
    # ===============

    @classmethod
    def hash(cls, data, **kwargs):
        """Return hash of data from byte string or unicode string."""

        if isinstance(data, str):
            data = data.encode('utf-8')
        ctx = cls(**kwargs)
        ctx.update(data)
        return ctx.finalize()

    @classmethod
    def hash_iter(cls, iterable, **kwargs):
        """Return hash of data from iterable of bytes."""

        ctx = cls(**kwargs)
        for chunk in iterable:
            ctx.update(chunk)
        return ctx.finalize()

    @classmethod
    def hash_fileobj(cls, fileobj, **kwargs):
        """Return hash of data from file object."""

        it = iter(functools.partial(fileobj.read, _CHUNK_SIZE), b'')
        return cls.hash_iter(it, **kwargs)

    @classmethod
    def hash_file(cls, filepath, **kwargs):
        """Return hash of data from file."""

        with open(filepath, 'rb') as f:
            return cls.hash_fileobj(f, **kwargs)

    @classmethod
    def hash_dir(cls, dirpath, **kwargs):
        """Return hash of data from directory."""

        try:
            digest_size = getattr(cls, 'digest_size')
        except AttributeError:
            digest_size = getattr(cls(**kwargs), 'digest_size')

        def _hash_dir(cls, dirpath, **kwargs):
            result = b'\x00' * digest_size
            with os.scandir(dirpath) as it:
                for entry in it:
                    if entry.is_dir():
                        value = cls.hash_dir(entry, **kwargs)
                    else:
                        value = cls.hash_file(entry, **kwargs)
                    result = bytes(x ^ y for x, y in zip(result, value))
            return result

        return _hash_dir(cls, dirpath, **kwargs)

    @classmethod
    def hash_fs(cls, path, **kwargs):
        """Return hash of data from filesystems."""

        if os.path.isdir(path):
            return cls.hash_dir(path, **kwargs)
        return cls.hash_file(path, **kwargs)


class ExtendableHash(Hash):
    """Abstract base class for extendable hash context."""

    @abc.abstractmethod
    def __init__(self):
        """Initialize the current context."""


class MD5(Hash):
    _cls = hashlib.md5
    block_size = 64
    digest_size = 16


class SHA1(Hash):
    _cls = hashlib.sha1
    block_size = 64
    digest_size = 20


class SHA224(Hash):
    _cls = hashlib.sha224
    block_size = 64
    digest_size = 28


class SHA256(Hash):
    _cls = hashlib.sha256
    block_size = 64
    digest_size = 32


class SHA384(Hash):
    _cls = hashlib.sha384
    block_size = 128
    digest_size = 48


class SHA512(Hash):
    _cls = hashlib.sha512
    block_size = 128
    digest_size = 64


class SHA3_224(Hash):
    _cls = hashlib.sha3_224
    block_size = 144
    digest_size = 28


class SHA3_256(Hash):
    _cls = hashlib.sha3_256
    block_size = 136
    digest_size = 32


class SHA3_384(Hash):
    _cls = hashlib.sha3_384
    block_size = 104
    digest_size = 48


class SHA3_512(Hash):
    _cls = hashlib.sha3_512
    block_size = 72
    digest_size = 64


class SHAKE128(ExtendableHash):
    _cls = hashlib.shake_128
    block_size = 168

    def __init__(self, *, digest_size=16):
        self._ctx = self._cls()
        self.digest_size = digest_size

    def finalize(self):
        return self._ctx.digest(self.digest_size)


class SHAKE256(ExtendableHash):
    _cls = hashlib.shake_256
    block_size = 136

    def __init__(self, *, digest_size=32):
        self._ctx = self._cls()
        self.digest_size = digest_size

    def finalize(self):
        return self._ctx.digest(self.digest_size)


class BLAKE2b(ExtendableHash):
    _cls = hashlib.blake2b
    block_size = 128
    max_digest_size = 64
    max_key_size = 64
    salt_size = 16
    person_size = 16

    def __init__(self, *, digest_size=64, key=b'', salt=b'', person=b'',
                 fanout=1, depth=1, leaf_size=0,
                 node_offset=0, node_depth=0,
                 inner_size=0, last_node=False):
        self._ctx = self._cls(
            digest_size=digest_size, key=key, salt=salt, person=person,
            fanout=fanout, depth=depth, leaf_size=leaf_size,
            node_offset=node_offset, node_depth=node_depth,
            inner_size=inner_size, last_node=last_node
        )
        self.digest_size = digest_size


class BLAKE2s(ExtendableHash):
    _cls = hashlib.blake2s
    block_size = 64
    max_digest_size = 32
    max_key_size = 32
    salt_size = 8
    person_size = 8

    def __init__(self, *, digest_size=32, key=b'', salt=b'', person=b'',
                 fanout=1, depth=1, leaf_size=0,
                 node_offset=0, node_depth=0,
                 inner_size=0, last_node=False):
        self._ctx = self._cls(
            digest_size=digest_size, key=key, salt=salt, person=person,
            fanout=fanout, depth=depth, leaf_size=leaf_size,
            node_offset=node_offset, node_depth=node_depth,
            inner_size=inner_size, last_node=last_node
        )
        self.digest_size = digest_size
