import hmac

__all__ = ['HMAC']

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
