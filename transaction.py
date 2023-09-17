# Tx is a class to parse and serialize bitcoin transactions
from format_converter import Converter
from helper_functions import read_varint, encode_varint
from script import Script
from hash_calculation import Hashes


converter = Converter()
hash = Hashes()

class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
    

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return f'tx: {self.id()}\nversion: {self.version}\ntx_ins:\n{tx_ins}tx_outs:\n{tx_outs}locktime: {self.locktime}'


    def id(self):
        return self.hash().hex()
    

    def hash(self):
        return hash.hash256(self.serialize())[::-1]


    @classmethod
    def parse(cls, stream, testnet=False):
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
    

    def serialize(self):
        '''Returns the byte serialization of the transaction'''
        result = converter.int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += converter.int_to_little_endian(self.locktime, 4)
        return result

    
    def fee(self, testnet=False):
        input_sum = 0
        output_sum = 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet=testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum
    

class TxIn:

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence


    def __repr__(self):
        return f'{self.prev_tx.hex()}:{self.prev_index}'


    @classmethod
    def parse(cls, stream):
        prev_tx = stream.read(32)[::-1]
        prev_index = converter.little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = converter.little_endian_to_int(stream.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)
    

    def serialize(self):
        result = self.prev_tx[::-1]
        result += converter.int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += converter.int_to_little_endian(self.sequence, 4)
        return result

    
    def value(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey


    def __repr__(self):
        return f'{self.amount}:{self.script_pubkey}'


    @classmethod
    def parse(cls, stream):
        amount = converter.little_endian_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)
        return cls(amount, script_pubkey)
    

    def serialize(self):  # <1>
        result = converter.int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result