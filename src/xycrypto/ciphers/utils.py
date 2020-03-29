from xycrypto.padding import create_padding


def determine_padding(padding, block_size):
    if padding is None:
        return None
    return create_padding(padding, block_size)


class PaddingWrapper(object):
    def __init__(self, padded_ctx, padding_ctx):
        self.padded_ctx = padded_ctx
        self.padding_ctx = padding_ctx

    def update(self, data):
        return self.padded_ctx.update(self.padding_ctx.update(data))

    def finalize(self):
        temp = self.padded_ctx.update(self.padding_ctx.finalize())
        return temp + self.padded_ctx.finalize()


def determine_encryptor(cipher, padding):
    encryptor = cipher.encryptor()
    if padding is None:
        return encryptor
    return PaddingWrapper(encryptor, padding.padder())


def determine_decryptor(cipher, padding):
    decryptor = cipher.decryptor()
    if padding is None:
        return decryptor
    return PaddingWrapper(padding.unpadder(), decryptor)
