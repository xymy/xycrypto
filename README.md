# xycrypto

## Usage

```python
>>> from xycrypto.hashes import SHA256

# Hash byte string using classmethod SHA256.hash.
>>> SHA256.hash(b'Hello, world!')
b'1_[\xdbv\xd0x\xc4;\x8a\xc0\x06NJ\x01da+\x1f\xcew\xc8i4[\xfc\x94\xc7X\x94\xed\xd3'

# If you want hex-string.
>>> SHA256.hash(b'Hello, world!').hex()
'315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3'

# Hash unicode string, encoded as UTF-8.
>>> SHA256.hash('Hello, world!').hex() 
'315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3'

# Hash file using classmethod SHA256.hash_file.
>>> SHA256.hash_file('path/to/file').hex()
'e69bd8e7e0dfadcda3f9785668c3918c469ebbe30fa42fb1158b638afdb9f7f7'

# Hash directory using classmethod SHA256.hash_dir.
>>> SHA256.hash_dir('path/to/dir').hex()
'746a5c6a0aac95507c96a192071ccdd762b5c69372d0cc66973a1e1dfcc73927'

# Context Interface.
>>> ctx = SHA256()
>>> ctx.update(b'Hello, world!')
>>> ctx.finalize().hex()
'315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3'
```

Support `MD5`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `SHAKE128`, `SHAKE256`, `BLAKE2b`, `BLAKE2s`.
