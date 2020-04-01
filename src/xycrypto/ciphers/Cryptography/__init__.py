from ._core_stream import (     # NOQA; isort:skip
    ChaCha20, RC4
)
from ._core_block import (      # NOQA; isort:skip
    AES, AES_ECB, AES_CBC, AES_CFB, AES_OFB, AES_CTR,
    Blowfish, Blowfish_ECB, Blowfish_CBC, Blowfish_CFB, Blowfish_OFB,
    Camellia, Camellia_ECB, Camellia_CBC, Camellia_CFB, Camellia_OFB, Camellia_CTR,
    CAST5, CAST5_ECB, CAST5_CBC, CAST5_CFB, CAST5_OFB,
    SEED, SEED_ECB, SEED_CBC, SEED_CFB, SEED_OFB,
    TripleDES, TripleDES_ECB, TripleDES_CBC, TripleDES_CFB, TripleDES_OFB
)

__all__ = [
    'ARC4', 'ChaCha20', 'RC4',
    'AES', 'AES_ECB', 'AES_CBC', 'AES_CFB', 'AES_OFB', 'AES_CTR',
    'Blowfish', 'Blowfish_ECB', 'Blowfish_CBC', 'Blowfish_CFB', 'Blowfish_OFB',
    'Camellia', 'Camellia_ECB', 'Camellia_CBC', 'Camellia_CFB', 'Camellia_OFB', 'Camellia_CTR',
    'CAST5', 'CAST5_ECB', 'CAST5_CBC', 'CAST5_CFB', 'CAST5_OFB',
    'DES', 'DES_ECB', 'DES_CBC', 'DES_CFB', 'DES_OFB',
    'SEED', 'SEED_ECB', 'SEED_CBC', 'SEED_CFB', 'SEED_OFB',
    'TripleDES', 'TripleDES_ECB', 'TripleDES_CBC', 'TripleDES_CFB', 'TripleDES_OFB',
]

ARC4 = RC4  # alias

# The Cryptography library does not provide DES, but we can use TripleDES with 64-bit key instead.
DES = TripleDES
DES_ECB = TripleDES_ECB
DES_CBC = TripleDES_CBC
DES_CFB = TripleDES_CFB
DES_OFB = TripleDES_OFB
