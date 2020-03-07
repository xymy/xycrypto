import functools
import hashlib
import os

__all__ = [
    'Hash', 'MD5', 'SHA1',
    'SHA224', 'SHA256', 'SHA384', 'SHA512',
    'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512', 'SHAKE128', 'SHAKE256',
    'BLAKE2b', 'BLAKE2s'
]


class Hash(object):
    _cls = hashlib.sha256
    block_size = 64
    digest_size = 32

    def __new__(cls, *args, **kwargs):
        if cls is Hash:
            raise NotImplementedError
        self = object.__new__(cls)
        return self

    def __init__(self):
        """Initialize the current context."""

        self._ctx = self._cls()

    def update(self, data):
        """Update the current context."""

        self._ctx.update(data)

    def finalize(self):
        """Finalize the current context and return the message digest as bytes."""

        try:
            finalize_func = getattr(self._ctx, 'digest')
        except AttributeError:
            finalize_func = getattr(self._ctx, 'finalize')
        return finalize_func()

    def copy(self):
        """Copy the current context."""

        return self._ctx.copy()

    @classmethod
    def hash(cls, data):
        """Return hash of data from memory."""

        ctx = cls()
        if isinstance(data, str):
            data = data.encode('utf-8')
        ctx.update(data)
        return ctx.finalize()

    @classmethod
    def hash_fileobj(cls, fileobj, chunk_size=0x100000):
        """Return hash of data from file object."""

        ctx = cls()
        for chunk in iter(functools.partial(fileobj.read, chunk_size), b''):
            ctx.update(chunk)
        return ctx.finalize()

    @classmethod
    def hash_file(cls, filepath):
        """Return hash of data from a file."""

        with open(filepath, 'rb') as f:
            return cls.hash_fileobj(f)

    @classmethod
    def hash_dir(cls, dirpath):
        """Return hash of data from a directory."""

        with os.scandir(dirpath) as it:
            result = b'\x00' * cls.digest_size
            for entry in it:
                if entry.is_dir():
                    value = cls.hash_dir(entry)
                else:
                    value = cls.hash_file(entry)
                result = bytes(x ^ y for x, y in zip(result, value))
            return result

    @classmethod
    def hash_fs(cls, path):
        """Return hash of data from a filesystem."""

        if os.path.isdir(path):
            return cls.hash_dir(path)
        return cls.hash_file(path)


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


class SHAKE128(Hash):
    _cls = hashlib.shake_128
    block_size = 168
    digest_size = 0


class SHAKE256(Hash):
    _cls = hashlib.shake_256
    block_size = 136
    digest_size = 0


class BLAKE2b(Hash):
    _cls = hashlib.blake2b
    block_size = 128
    digest_size = 64

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


class BLAKE2s(Hash):
    _cls = hashlib.blake2s
    block_size = 64
    digest_size = 32

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
