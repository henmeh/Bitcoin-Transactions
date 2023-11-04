from format_converter import Converter

converter = Converter()

SIGHASH_ALL = 1

def read_varint(stream: bytearray) -> int:
    i = stream.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return converter.little_endian_to_int(stream.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return converter.little_endian_to_int(stream.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return converter.little_endian_to_int(stream.read(8))
    else:
        # anything else is just the integer
        return i

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + converter.int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + converter.int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + converter.int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))