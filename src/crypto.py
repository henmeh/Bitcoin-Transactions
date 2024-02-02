import hashlib

from Crypto.Hash import RIPEMD160


def hash160(data: bytes) -> bytes:
    hash_160 = RIPEMD160.new()
    hash_160.update(hashlib.sha256(data).digest())

    return hash_160.digest()


def dhash160(data: bytes) -> bytes:

    sha_256 = hashlib.sha256(data).digest()

    hash_160 = RIPEMD160.new()
    hash_160.update(sha_256)

    return hash_160.digest()


def hash256(data: bytes) -> bytes:

    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def sha256(data: bytes) -> bytes:

    return hashlib.sha256(data).digest()
