from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher  # NOQA
from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES  # NOQA
from cryptography.hazmat.primitives.ciphers.modes import CBC, ECB  # NOQA

backend = default_backend()
