from io import BytesIO
from src.helper import read_varint, little_endian_to_int, int_to_little_endian, encode_varint


def p2pk_script(pub_key: bytes) -> "Script":
    return Script([pub_key, 0xac])


def p2pkh_script(h160: bytes) -> "Script":
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


def p2sh_script(h160: bytes) -> "Script":
    return Script([0xa9, h160, 0x87])


def p2wpkh_script(h160: bytes) -> "Script":
    return Script([0x00, h160])


def p2wsh_script(h256: bytes) -> "Script":
    return Script([0x00, h256])

class Script:
    def __init__(self, commands: list[bytes] = None):
        if commands is None:
            self.commands = []
        else:
            self.commands = commands


    @classmethod
    def parse_script(cls, script_as_byte: BytesIO) -> "Script":
        commands = []
        script_length = read_varint(script_as_byte)

        count = 0
        while count < script_length:
            current_byte = script_as_byte.read(1)
            count += 1

            current_byte_value = current_byte[0]

            if current_byte_value >= 1 and current_byte_value <=75:
                commands.append(script_as_byte.read(current_byte_value))
                count += current_byte_value
            
            elif current_byte_value == 76:
                data_length = little_endian_to_int(script_as_byte.read(1))
                commands.append(script_as_byte.read(data_length))
                count += data_length + 1  # data_lenght for amount of bytes we consumed + 1 for the actual length byte
            
            elif current_byte_value == 77:
                data_length = little_endian_to_int(script_as_byte.read(2))
                commands.append(script_as_byte.read(data_length))
                count += data_length + 2  # data_lenght for amount of bytes we consumed + 2 for the actual length byte
            
            else:
                commands.append(current_byte_value)
        
        if count != script_length:
            raise SyntaxError("parsing script failed")
        
        return cls(commands)
    

    def serialize_script(self) -> str:
        serialized_script = b''
        for command in self.commands:
            if isinstance(command, int):
                serialized_script += int_to_little_endian(command, 1)
            else:
                length = len(command)
                if length < 75:
                    serialized_script += int_to_little_endian(length, 1)
                elif length > 75 and length < 256:
                    serialized_script += int_to_little_endian(76, 1)
                    serialized_script += int_to_little_endian(length, 1)
                elif length > 255 and length < 521:
                    serialized_script += int_to_little_endian(77, 1)
                    serialized_script += int_to_little_endian(length, 2)
                else:
                    raise ValueError("command is too long")
                serialized_script += command
        script_length = encode_varint(len(serialized_script))

        return script_length + serialized_script
