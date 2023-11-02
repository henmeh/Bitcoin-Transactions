import hashlib
from Crypto.Hash import RIPEMD160


class Hashes:

    def __init__(self):
        pass


    def hash160(self, data: bytes) -> bytes:
        # a sha256 followed by ripemd160
        hash160 = RIPEMD160.new()
        hash160.update(hashlib.sha256(data).digest())

        return hash160.digest()


    def dhash160(self, data):

        data_in_bytes = bytes.fromhex(data)

        sha256= hashlib.sha256(data_in_bytes).digest() 

        hash160 = RIPEMD160.new()
        hash160.update(sha256)

        return hash160.hexdigest()


    def hash256(self, data: str) -> bytes:

        return hashlib.sha256(hashlib.sha256(data).digest()).digest()


    def sha256(self, data: bytes) -> bytes:

        return hashlib.sha256(data).digest()
