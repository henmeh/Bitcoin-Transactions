from hash_calculation import Hashes
import base58



class Converter:

    def __init__(self):
        self.BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        self.hash = Hashes()


    def convert_string_to_hex(self, string: str) -> str:

        string_in_bytes: bytes = string.encode()
        return string_in_bytes.hex()


    def convert_endianes_hex_str(self, number: str) -> str:

        number_in_bytes: bytes = bytes.fromhex(number)
        number_in_bytes_reversed: bytes = number_in_bytes[::-1]
        return number_in_bytes_reversed.hex()


    def convert_format_satoshi_amounts(self, amount: int) -> int:
        
        satoshi_amount: str = hex(amount)[2:]
        print(int(satoshi_amount,16).to_bytes(8, "little").hex())
        return int(satoshi_amount,16).to_bytes(8, "little").hex()


    def little_endian_to_int(self, b: bytes) -> int:
        return int.from_bytes(b, 'little')


    def int_to_little_endian(self, n: int, length: int) -> bytes:
        return n.to_bytes(length, 'little')
    

    def encode_base58(self, s: bytes) -> str:
        count = 0
        for c in s:  
            if c == 0:
                count += 1
            else:
                break
        num = int.from_bytes(s, 'big')
        prefix = '1' * count
        result = ''
        while num > 0:  
            num, mod = divmod(num, 58)
            result = self.BASE58_ALPHABET[mod] + result
        return prefix + result
    

    def encode_base58_checksum(self, b: bytes) -> str:
        return self.encode_base58(b + self.hash256.hash256(b)[:4])


    def decode_base58(self, s: str) -> bytes:
        num = 0
        for c in s:
            num *= 58
            num += self.BASE58_ALPHABET.index(c)
        combined = num.to_bytes(25, byteorder='big')
        checksum = combined[-4:]
        if self.hash.hash256(combined[:-4])[:4] != checksum:
            raise ValueError('bad address: {} {}'.format(checksum, self.hash.hash256(combined[:-4])[:4]))
        return combined[1:-4]


    def convert_private_key_wif_to_int(self, private_key_wif: str) -> int:
        
        private_key_bytes = base58.b58decode_check(private_key_wif)
        private_key_hex = private_key_bytes.hex()[2:-2]
        private_key_int = int(private_key_hex, 16)

        return private_key_int