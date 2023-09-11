import hashlib
from Crypto.Hash import RIPEMD160


class Hashes:

    def __init__(self):
        pass


    def hash160(self, data):

        data_in_bytes = bytes.fromhex(data)

        #sha256= hashlib.sha256(data_in_bytes).digest() 

        hash160 = RIPEMD160.new()
        hash160.update(data_in_bytes)

        return hash160.hexdigest()


    def dhash160(self, data):

        data_in_bytes = bytes.fromhex(data)

        sha256= hashlib.sha256(data_in_bytes).digest() 

        hash160 = RIPEMD160.new()
        hash160.update(sha256)

        return hash160.hexdigest()


    def hash256(self, data):

        data_in_bytes = bytes.fromhex(data)

        hash256 = hashlib.sha256(hashlib.sha256(data_in_bytes).digest()).hexdigest()

        return hash256


    def sha256(self, data):

        data_in_bytes = bytes.fromhex(data)

        sha256 = hashlib.sha256(data_in_bytes).hexdigest()

        return sha256
