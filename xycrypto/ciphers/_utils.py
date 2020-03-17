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


def _perform_encryption(cipher, data):
    encryptor = cipher.encryptor()
    temp = encryptor.update(data)
    return temp + encryptor.finalize()


def _perform_decryption(cipher, data):
    decryptor = cipher.decryptor()
    temp = decryptor.update(data)
    return temp + decryptor.finalize()


def _make_X(cipher_attrs):
    def _X(cipher_base):
        name = cipher_base.__name__ + '_' + cipher_attrs['name']
        return type(name, (cipher_base,), cipher_attrs)
    return _X
