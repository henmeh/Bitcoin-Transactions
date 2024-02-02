from io import BytesIO

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode_base58(s: bytes) -> str:
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, "big")
    prefix = "1" * count
    result = ""
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def little_endian_to_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def int_to_little_endian(n: int, length: int) -> bytes:
    return n.to_bytes(length, "little")


def read_varint(stream: BytesIO) -> int:
    i = stream.read(1)[0]
    if i == 0xFD:
        # 0xfd means the next two bytes are the number
        return_value = little_endian_to_int(stream.read(2))
    elif i == 0xFE:
        # 0xfe means the next four bytes are the number
        return_value = little_endian_to_int(stream.read(4))
    elif i == 0xFF:
        # 0xff means the next eight bytes are the number
        return_value = little_endian_to_int(stream.read(8))
    else:
        # anything else is just the integer
        return_value =  i
    return return_value


def encode_varint(integer: int) -> bytes:
    if integer < 0xFD:
        return_value = bytes([integer])
    elif integer < 0x10000:
        return_value = b"\xfd" + int_to_little_endian(integer, 2)
    elif integer < 0x100000000:
        return_value = b"\xfe" + int_to_little_endian(integer, 4)
    elif integer < 0x10000000000000000:
        return_value = b"\xff" + int_to_little_endian(integer, 8)
    else:
        raise ValueError(f"integer too large: {integer}")
    return return_value