import hashlib
import hmac
from io import BytesIO

from src.crypto import hash160, hash256
from src.ec_point import ECPoint
from src.fieldelement import FieldElement
from src.helper import encode_base58


class Secp256k1:

    p = 2 ** 256 - 2 ** 32 - 977
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    a = FieldElement(0, p)
    b = FieldElement(7, p)
    G = ECPoint(
        FieldElement(
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, p
        ),
        FieldElement(
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, p
        ),
        a,
        b,
    )

    def sign_data(self, private_key: int, data: int) -> "Signature":
        temp_private_key = self.deterministic_k(private_key, data)
        point_r = temp_private_key * self.G
        r = point_r.x_coordinate.num
        s = (
            (
                FieldElement(data, self.n)
                + FieldElement(private_key, self.n) * FieldElement(r, self.n)
            )
            / FieldElement(temp_private_key, self.n)
        ).num

        return Signature(r, s)

    def verify_signature(
        self, public_key: "PublicKey", signature: "Signature", data: int
    ) -> bool:
        w = pow(signature.s, self.n - 2, self.n)
        u1 = (w * data) % self.n
        u2 = (w * signature.r) % self.n
        point = u1 * self.G + u2 * public_key

        return point.x_coordinate.num == signature.r

    def deterministic_k(self, private_key: int, data: int) -> int:
        k = b"\x00" * 32
        v = b"\x01" * 32
        if data > self.n:
            data -= self.n
        z_bytes = data.to_bytes(32, "big")
        private_key_bytes = private_key.to_bytes(32, "big")
        s256 = hashlib.sha256
        k = hmac.new(k, v + b"\x00" + private_key_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b"\x01" + private_key_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, "big")
            if candidate >= 1 and candidate < self.n:
                return candidate
            k = hmac.new(k, v + b"\x00", s256).digest()
            v = hmac.new(k, v, s256).digest()


class Signature:
    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

    def __repr__(self):
        return f"Signature({self.r},{self.s})"

    # Distinguished Encoding Rules
    # 30 + length(r und s) + 02 + length(r) + r (big endian prepend with 00 if first byte r >= 80)
    # and same for s
    def der(self) -> bytes:
        r_bytes = self.r.to_bytes(32, byteorder="big")
        r_bytes = r_bytes.lstrip(b"\x00")
        if r_bytes[0] & 0x80:
            r_bytes = b"\x00" + r_bytes
        result = bytes([2, len(r_bytes)]) + r_bytes

        s_bytes = self.s.to_bytes(32, byteorder="big")
        s_bytes = s_bytes.lstrip(b"\x00")
        if s_bytes[0] & 0x80:
            s_bytes = b"\x00" + s_bytes
        result += bytes([2, len(s_bytes)]) + s_bytes

        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin: bytes) -> "Signature":
        stream = BytesIO(signature_bin)
        compound = stream.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = stream.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = stream.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = stream.read(1)[0]
        r = int.from_bytes(stream.read(rlength), "big")
        marker = stream.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = stream.read(1)[0]
        s = int.from_bytes(stream.read(slength), "big")
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature has wrong length")
        return cls(r, s)


class PrivateKey(Secp256k1):
    def __init__(self, private_key: int):
        self.private_key = private_key
        self.public_key = private_key * self.G

    def get_private_key_int(self) -> int:
        return self.private_key

    def get_public_key(self) -> "PublicKey":
        return PublicKey(self.public_key.x_coordinate, self.public_key.y_coordinate)

    def convert_to_wif_format(
        self, compressed: bool = True, testnet: bool = False
    ) -> str:
        private_key_bytes = self.private_key.to_bytes(32, "big")
        if testnet:
            prefix = b"\xef"
        else:
            prefix = b"\x80"

        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        checksum = hash256(prefix + private_key_bytes + suffix)[:4]

        return encode_base58(prefix + private_key_bytes + suffix + checksum)


class PublicKey(Secp256k1, ECPoint):
    def __init__(self, x_coordinate, y_coordinate, a=None, b=None):
        a = self.a
        b = self.b
        if isinstance(x_coordinate, int):
            super().__init__(
                FieldElement(x_coordinate, self.p),
                FieldElement(y_coordinate, self.p),
                a,
                b,
            )
        else:
            super().__init__(x_coordinate, y_coordinate, a, b)

    # SEC == Standards for Efficient Cryptography
    def sec_format(self, compressed: bool = True) -> bytes:
        if compressed:
            y_coordinate_is_even = self.y_coordinate.num % 2 == 0
            if y_coordinate_is_even:
                return_string = b"\x02" + self.x_coordinate.num.to_bytes(32, "big")
            else:
                return_string = b"\x03" + self.x_coordinate.num.to_bytes(32, "big")
        else:
            return_string = (
                b"\x04"
                + self.x_coordinate.num.to_bytes(32, "big")
                + self.y_coordinate.num.to_bytes(32, "big")
            )
        return return_string

    @classmethod
    def parse_public_key(cls, public_key_sec_bin: bytes) -> "PublicKey":
        public_key_first_byte = public_key_sec_bin[0]
        is_uncompressed = public_key_first_byte == 4
        is_even = public_key_first_byte == 2

        if is_uncompressed:
            x_coordinate = int.from_bytes(public_key_sec_bin[1:33], "big")
            y_coordinate = int.from_bytes(public_key_sec_bin[33:65], "big")
            return PublicKey(x_coordinate, y_coordinate)

        x = FieldElement(int.from_bytes(public_key_sec_bin[1:], "big"), cls.p)
        alpha = x ** 3 + cls.b
        beta = alpha.sqrt()

        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = FieldElement(cls.p - beta.num, cls.p)
        else:
            even_beta = FieldElement(cls.p - beta.num, cls.p)
            odd_beta = beta
        if is_even:
            return PublicKey(x.num, even_beta.num)
        else:
            return PublicKey(x.num, odd_beta.num)

    def converto_to_base58_address(
        self, compressed: bool = True, testnet: bool = False
    ) -> str:
        hash_160 = hash160(self.sec_format(compressed=compressed))
        if testnet:
            prefix = b"\x6f"
        else:
            prefix = b"\x00"
        checksum = hash256(prefix + hash_160)[:4]

        return encode_base58(prefix + hash_160 + checksum)
