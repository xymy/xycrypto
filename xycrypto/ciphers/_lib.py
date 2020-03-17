from cryptography.hazmat.backends import default_backend    # NOQA; isort:skip
from cryptography.hazmat.primitives.ciphers import Cipher   # NOQA; isort:skip
from cryptography.hazmat.primitives.ciphers.algorithms import (     # NOQA; isort:skip
    AES, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (          # NOQA; isort:skip
    ECB, CBC, OFB, CFB
)

backend = default_backend()
