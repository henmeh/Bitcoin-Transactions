import hashlib
from Crypto.Hash import RIPEMD160


class Crypto:

    def hash160(self, data):
        hash160 = RIPEMD160.new()
        hash160.update(hashlib.sha256(data).digest())

        return hash160.digest()
        

    def dhash160(self, data):

        sha256= hashlib.sha256(data).digest() 

        hash160 = RIPEMD160.new()
        hash160.update(sha256)

        return hash160.digest()


    def hash256(self, data):

        return hashlib.sha256(hashlib.sha256(data).digest()).digest()


    def sha256(self, data):

        return hashlib.sha256(data).digest()