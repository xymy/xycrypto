# xycrypto

## Installation

Require Python 3.6+.

```shell
pip install -U xycrypto
```

## Ciphers

The `xycrypto` provides simple and elegant interfaces for ciphers.

The cryptography components for ciphers we support:
- Available *stream cipher*: `ChaCha20`, `RC4`.
- Available *block cipher*: `AES`, `Blowfish`, `Camellia`, `CAST5`, `DES`, `IDEA`, `SEED`, `TripleDES`.
- Available *mode*: `ECB`, `CBC`, `CFB`, `OFB`, `CTR`.
- Available *padding*: `PKCS7`, `ANSIX923`, `ISO10126`.

### Usage

**Firstly**, you should import the cipher class from the package `xycrypto.ciphers`. The cipher class follows the following naming conventions:
- For *stream cipher*, `<cipher_name>`.
- For *block cipher*, `<cipher_name>_<mode>`.

```python
>>> from xycrypto.ciphers import AES_CBC
```

**Secondly**, you should create the instance of the cipher class. In this case, you should provide some arguments:
- *key* for all ciphers.
- *iv* for *block cipher* in `ECB`, `CBC`, `OFB`, `CFB` mode.
- *nonce* for *block cipher* in `CTR` mode.
- *padding* for *block cipher* in `ECB`, `CBC` mode.

```python
# The len(key) is 16 bytes for AES-128, you can use 32 bytes key for AES-256.
>>> key = b'0123456789abcdef'
# Note len(iv) should be equal to AES_CBC.block_size.
>>> iv = b'0123456789abcdef'
# We use PKCS7 padding.
>>> cipher = AES_CBC(key, iv=iv, padding='PKCS7')
```

**Finally**, call `encrypt` or `decrypt` method to encrypt or decrypt data respectively.

```python
>>> plaintext = b'Welcome to xycrypto!'
>>> ciphertext = cipher.encrypt(plaintext) 
>>> ciphertext
b'3\x0f\xad\xa6\x17\xc4}\xb9\t\x17\xf8\xae\xbb\xa2t\xb9o\xf2\xf6\x16\t\x0803\xaci\x0c\x19q\x9d\xa3O'
>>> cipher.decrypt(ciphertext)
b'Welcome to xycrypto!'
```

### Example

```python
>>> from xycrypto.ciphers import AES_CBC

# The len(key) is 16 bytes for AES-128, you can use 32 bytes key for AES-256.
>>> key = b'0123456789abcdef'
# Note len(iv) should be equal to AES_CBC.block_size.
>>> iv = b'0123456789abcdef'
# We use PKCS7 padding.
>>> cipher = AES_CBC(key, iv=iv, padding='PKCS7')

>>> plaintext = b'Welcome to xycrypto!'
>>> ciphertext = cipher.encrypt(plaintext) 
>>> ciphertext
b'3\x0f\xad\xa6\x17\xc4}\xb9\t\x17\xf8\xae\xbb\xa2t\xb9o\xf2\xf6\x16\t\x0803\xaci\x0c\x19q\x9d\xa3O'
>>> cipher.decrypt(ciphertext)
b'Welcome to xycrypto!'
```
