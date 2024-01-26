from src.ec_point import ECPoint
from src.fieldelement import FieldElement

class Secp256k1:

    p = 2**256 - 2**32 - 977
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    a = FieldElement(0, p)
    b = FieldElement(7, p)
    G = ECPoint(FieldElement(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, p), FieldElement(0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, p), a, b)

                        
    def sign_data(self):
        return 0
    

    def verify_signature(self, public_key: tuple, signature: tuple, data):
        
        pub_key = ECPoint(FieldElement(public_key[0], self.p), FieldElement(public_key[1], self.p), self.a, self.b)
        r = signature[0]
        s = signature[1]

        w = pow(s, self.n - 2, self.n)
        u1 = (w * data) % self.n
        u2 = (w * r) % self.n
        P = u1 * self.G + u2 * pub_key

        return P.x_coordinate.num == r