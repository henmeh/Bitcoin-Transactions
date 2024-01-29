from src.helper import Converter


class Transaction:

    def __init__(self, version, number_of_inputs):
        self.version = version
        self.number_of_inputs = number_of_inputs

    @classmethod
    def parse(cls, transaction_as_byte_stream, testnet=False):
        version = Converter().little_endian_to_int(transaction_as_byte_stream.read(4))
        number_of_inputs = Converter().read_varint(transaction_as_byte_stream)

        return cls(version, number_of_inputs)