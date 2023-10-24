class ECDSA:

    def __init__(self, curve):
        if curve == "secp256k1":
            #y² = x³ +a*x + b mod p
            self.a = 0
            self.b = 7
            self.p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
            self.max_points = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            self.max_points_int: int = int(self.max_points, 16)
            self.generator_point = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)

    
    def gcdExtended(self, a, b):

        if a == 0 :
            return b,0,1
                
        gcd,x1,y1 = self.gcdExtended(b%a, a)
        x = y1 - (b//a) * x1
        y = x1
        
        return gcd,x,y


    def ec_addition(self, P1, P2):
        
        s = ((P2[1] - P1[1]) * self.gcdExtended(self.p, (P2[0] - P1[0]))[2]) % self.p
        x = (pow(s,2) - P1[0] - P2[0]) % self.p
        y = (s * (P1[0] - x) - P1[1]) % self.p

        return (x,y)


    def ec_doubling(self, P1):
        
        s = ((3 * pow(P1[0], 2) + self.a) * self.gcdExtended(self.p, (2 * P1[1]))[2]) % self.p
        x = (pow(s, 2) - 2* P1[0]) % self.p
        y = (s * (P1[0] - x) - P1[1]) % self.p

        return (x,y)


    def ec_multiply(self, private_key: int):

        if 0 < private_key <= self.max_points_int:
            key_public = self.generator_point

            #to speed up calculations we use the double and add algorithmus
            key_priv_binary = bin(private_key)[2:]
            
            for i in range(1, len(key_priv_binary)):
                key_public = self.ec_doubling(key_public)
                if (key_priv_binary[i]=="1"):
                    key_public = self.ec_addition(key_public, self.generator_point)

        else:
            print("This is an invalid private key!")

        return (key_public[0], key_public[1])


    def sign_data(self, hash_of_data_to_sign: str, key_private: int) -> int:

        random_number = 123456789

        x_random_signing_point, _ = self.ec_multiply(random_number)
        r = x_random_signing_point
        s = (hash_of_data_to_sign + r * key_private) * (self.gcdExtended(self.max_points_int, random_number)[2]) % self.max_points_int

        #use the low s value (BIP 62: Dealing with malleability)
        if (s > self.max_points_int / 2):
            s = self.max_points_int - s
        
        return (r, s)
    
    def der(self, r: int, s: int) -> bytes:
        
        rbin = r.to_bytes(32, 'big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin

        sbin = s.to_bytes(32, 'big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        
        return bytes([0x30, len(result)]) + result
    

    def verify_signature(self, hash_of_data_to_sign, s, public_key, r):

        w = self.gcdExtended(self.max_points_int, s)[2]
        u1 = (w * hash_of_data_to_sign) % self.max_points_int
        u2 = (w * r) % self.max_points_int
        xu1, yu1 = self.ec_multiply(u1)
        xu2, yu2 = self.ec_multiply(u2)
        x, y = self.ec_addition((xu1, yu1), (xu2, yu2))

        return x == r % self.max_points_int