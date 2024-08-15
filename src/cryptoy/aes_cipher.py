from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)


def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    c = AESGCM(key)
    return c.encrypt(nonce, msg, None)


def decrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    c = AESGCM(key)
    return c.decrypt(nonce, msg, None)

