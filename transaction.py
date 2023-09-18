# Tx is a class to parse and serialize bitcoin transactions
from format_converter import Converter
from helper_functions import read_varint, encode_varint
from script import Script
from hash_calculation import Hashes


converter = Converter()
hash = Hashes()

class Tx:

    def __init__(self, version: int, tx_ins: list, tx_outs: list, locktime: int, testnet: bool=False) -> "Tx":
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
    

    def __repr__(self) -> str:
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return f'tx: {self.id()}\nversion: {self.version}\ntx_ins:\n{tx_ins}tx_outs:\n{tx_outs}locktime: {self.locktime}'


    def id(self) -> str:
        return self.hash().hex()
    

    def hash(self) -> bytes:
        return hash.hash256(self.serialize())[::-1]


    @classmethod
    def parse(cls, stream: bytes, testnet: bool=False) -> "Tx":
        version = converter.little_endian_to_int(stream.read(4))
        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))
        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))
        locktime = converter.little_endian_to_int(stream.read(4))

        return cls(version, inputs, outputs, locktime, testnet=testnet)
    

    def serialize(self) -> bytes:
        result = converter.int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += converter.int_to_little_endian(self.locktime, 4)
        print(result.hex())
        return result

    
    def fee(self, testnet: bool=False) -> int:
        input_sum = 0
        output_sum = 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet=testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum
    

class TxIn:

    def __init__(self, prev_tx: bytes, prev_index: int, script_sig: bytes=None, sequence: int=0xffffffff) -> "TxIn":
        self.prev_tx: bytes = prev_tx
        self.prev_index: int = prev_index
        if script_sig is None:
            self.script_sig: "Script" = Script()
        else:
            self.script_sig: bytes = script_sig
        self.sequence: int = sequence


    def __repr__(self) -> str:
        return f'{self.prev_tx.hex()}:{self.prev_index}'


    @classmethod
    def parse(cls, stream: bytes) -> "TxIn":
        prev_tx: bytes = stream.read(32)[::-1]
        prev_index: int = converter.little_endian_to_int(stream.read(4))
        script_sig: bytes = Script.parse(stream)
        sequence: int = converter.little_endian_to_int(stream.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)
    

    def serialize(self) -> bytes:
        result: bytes = self.prev_tx[::-1]
        result += converter.int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += converter.int_to_little_endian(self.sequence, 4)
        return result


class TxOut:

    def __init__(self, amount: int, script_pubkey: bytes) -> "TxOut":
        self.amount: int = amount
        self.script_pubkey: bytes = script_pubkey


    def __repr__(self) -> str:
        return f'{self.amount}:{self.script_pubkey}'


    @classmethod
    def parse(cls, stream: bytes) -> "TxOut":
        amount: int = converter.little_endian_to_int(stream.read(8))
        script_pubkey: bytes = Script.parse(stream)
        return cls(amount, script_pubkey)
    

    def serialize(self) -> bytes:
        result: bytes = converter.int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result
    


def test_tx_parser_input_tx():
    from io import BytesIO
 
    raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    stream = BytesIO(raw_tx)
    tx = Tx.parse(stream)
    print(tx)
    
test_tx_parser_input_tx()