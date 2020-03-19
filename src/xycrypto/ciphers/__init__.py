from ._stream import (                  # NOQA; isort:skip
    RC4, ChaCha20
)
from ._block_AES import (               # NOQA; isort:skip
    AES_ECB, AES_CBC, AES_CFB, AES_OFB, AES_CTR
)
from ._block_TripleDES import (         # NOQA; isort:skip
    TripleDES_ECB, TripleDES_CBC, TripleDES_CFB, TripleDES_OFB, TripleDES_CTR
)

__all__ = [
    'ARC4', 'ChaCha20', 'RC4',
    'AES_ECB', 'AES_CBC', 'AES_CFB', 'AES_OFB', 'AES_CTR',
    'DES_ECB', 'DES_CBC', 'DES_CFB', 'DES_OFB', 'DES_CTR',
    'TripleDES_ECB', 'TripleDES_CBC', 'TripleDES_CFB', 'TripleDES_OFB', 'TripleDES_CTR'
]

ARC4 = RC4                              # alias

# The Cryptography library does not provide DES, but we can use TripleDES with 64-bit key instead.
DES_ECB = TripleDES_ECB
DES_CBC = TripleDES_CBC
DES_CFB = TripleDES_CFB
DES_OFB = TripleDES_OFB
DES_CTR = TripleDES_CTR
