
class Converter:

    def __init__(self):
        pass


    def convert_string_to_hex(string):

        string_in_bytes = string.encode()

        return string_in_bytes.hex()


    def convert_endianes(number):

        number_in_bytes = bytes.fromhex(number)
        number_in_bytes_reversed = number_in_bytes[::-1]
        number_in_hex_reversed = number_in_bytes_reversed.hex()

        return number_in_hex_reversed


    def format_satoshi_amounts(amount):
        
        satoshi_amount = hex(amount)[2:]
        
        return int(satoshi_amount,16).to_bytes(8, "little").hex()

