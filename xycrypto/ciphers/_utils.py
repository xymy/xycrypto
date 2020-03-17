from xycrypto.padding import _lookup_padding


def _determine_padding(padding, block_size):
    if padding is None:
        return None
    padding = _lookup_padding(padding)
    return padding(block_size)


def _determine_encryptor(cipher, padding):
    encryptor = cipher.encryptor()
    if padding is None:
        return encryptor
    return padding.wrap_encryptor(encryptor)


def _determine_decryptor(cipher, padding):
    decryptor = cipher.decryptor()
    if padding is None:
        return decryptor
    return padding.wrap_decryptor(decryptor)
