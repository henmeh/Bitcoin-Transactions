from io import BytesIO

from src.helper import little_endian_to_int, read_varint


class Transaction:
    def __init__(self, version: int, number_of_inputs: int):
        self.version = version
        self.number_of_inputs = number_of_inputs

    @classmethod
    def parse(
        cls, transaction_as_byte_stream: BytesIO, testnet: bool = False
    ) -> "Transaction":
        version = little_endian_to_int(transaction_as_byte_stream.read(4))
        number_of_inputs = read_varint(transaction_as_byte_stream)

        return cls(version, number_of_inputs)
