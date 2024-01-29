class BASE58:
    
    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    def encode_base58(self, s):
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


class Converter:

    def little_endian_to_int(self, bytes):
        return int.from_bytes(bytes, 'little')
    

    def int_to_little_endian(self, n, length):
        return n.to_bytes(length, 'little')


    def read_varint(self, stream):
        i = stream.read(1)[0]
        if i == 0xfd:
            # 0xfd means the next two bytes are the number
            return self.little_endian_to_int(stream.read(2))
        elif i == 0xfe:
            # 0xfe means the next four bytes are the number
            return self.little_endian_to_int(stream.read(4))
        elif i == 0xff:
            # 0xff means the next eight bytes are the number
            return self.little_endian_to_int(stream.read(8))
        else:
            # anything else is just the integer
            return i
    

    def encode_varint(self, integer):
        if integer < 0xfd:
            return bytes([integer])
        elif integer < 0x10000:
            return b'\xfd' + self.int_to_little_endian(integer, 2)
        elif integer < 0x100000000:
            return b'\xfe' + self.int_to_little_endian(integer, 4)
        elif integer < 0x10000000000000000:
            return b'\xff' + self.int_to_little_endian(integer, 8)
        else:
            raise ValueError(f'integer too large: {integer}')
