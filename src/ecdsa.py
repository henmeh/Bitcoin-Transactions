from src.ec_point import ECPoint
from src.fieldelement import FieldElement
import hashlib
import hmac

class Secp256k1:

    p = 2**256 - 2**32 - 977
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    a = FieldElement(0, p)
    b = FieldElement(7, p)
    G = ECPoint(FieldElement(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, p), FieldElement(0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, p), a, b)

                        
    def sign_data(self, private_key, data):
        temp_private_key = self.deterministic_k(private_key, data)
        point_r = temp_private_key * self.G
        r = point_r.x_coordinate.num
        s = ((FieldElement(data, self.n) + FieldElement(private_key, self.n) * FieldElement(r, self.n)) / FieldElement(temp_private_key, self.n)).num

        return Signature(r, s)
    

    def verify_signature(self, public_key: tuple, signature, data):
        
        pub_key = ECPoint(FieldElement(public_key[0], self.p), FieldElement(public_key[1], self.p), self.a, self.b)

        w = pow(signature.s, self.n - 2, self.n)
        u1 = (w * data) % self.n
        u2 = (w * signature.r) % self.n
        point = u1 * self.G + u2 * pub_key

        return point.x_coordinate.num == signature.r
    

    def deterministic_k(self, private_key, data):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if data > self.n:
            data -= self.n
        z_bytes = data.to_bytes(32, 'big')
        private_key_bytes = private_key.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + private_key_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + private_key_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < self.n:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()


class Signature:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    
    def __repr__(self):
        return f'Signature({self.r},{self.s})'


class PrivateKey(Secp256k1):

    def __init__(self, private_key):
        self.private_key = private_key
        self.public_key = private_key * self.G
    

    def get_private_key_int(self):
        return self.private_key
    
    
    def get_public_key_coordinates(self):
        return (self.public_key.x_coordinate.num, self.public_key.y_coordinate.num)


class PublicKey(Secp256k1, ECPoint):

    def __init__(self, x_coordinate, y_coordinate):
        if type(x_coordinate) == int:
            super().__init__(FieldElement(x_coordinate, self.p), FieldElement(y_coordinate, self.p), self.a, self.b)
        else:
            super().__init__(x_coordinate, y_coordinate, self.a, self.b)
    

    #SEC == Standards for Efficient Cryptography
    def sec_format_uncompressed(self):
        return b'\x04' + self.x_coordinate.num.to_bytes(32, 'big') + self.y_coordinate.num.to_bytes(32, 'big')
    

    def sec_format_compressed(self):
        y_coordinate_is_even = self.y_coordinate.num % 2 == 0

        if y_coordinate_is_even:
            return b'\x02' + self.x_coordinate.num.to_bytes(32, 'big')
        else:
            return b'\x03' + self.x_coordinate.num.to_bytes(32, 'big')
    

    @classmethod
    def parse_public_key(self, public_key_sec_bin):
        public_key_first_byte = public_key_sec_bin[0] 
        is_uncompressed = public_key_first_byte == 4
        is_even = public_key_first_byte == 2
        
        if is_uncompressed:
            x_coordinate = int.from_bytes(public_key_sec_bin[1:33], 'big')
            y_coordinate = int.from_bytes(public_key_sec_bin[33:65], 'big')
            return PublicKey(x_coordinate, y_coordinate)
        
        x = FieldElement(int.from_bytes(public_key_sec_bin[1:], 'big'), self.p)
        alpha = x**3 + self.b
        beta = alpha.sqrt()

        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = FieldElement(self.p - beta.num, self.p)
        else:
            even_beta = FieldElement(self.p - beta.num, self.p)
            odd_beta = beta
        if is_even:
            return PublicKey(x.num, even_beta.num)
        else:
            return PublicKey(x.num, odd_beta.num)
