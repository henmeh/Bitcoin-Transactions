import json
import requests
from io import BytesIO

from src.helper import little_endian_to_int, read_varint, int_to_little_endian, encode_varint
from src.crypto import hash256
from src.script import Script


class CTx:
    def __init__(self, version: int, tx_ins: list["CTxIn"], tx_outs: list["CTxOut"], locktime: int, is_testnet: bool, is_segwit:bool):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.is_testnet = is_testnet
        self.is_segwit = is_segwit

    
    def id(self):
        return hash256(self.serialize_transaction())[::-1]
    

    @classmethod
    def parse_transaction(cls, transaction_as_byte_stream: BytesIO, is_testnet: bool = False, is_segwit: bool = False) -> "CTx":
        version = little_endian_to_int(transaction_as_byte_stream.read(4))
        number_of_inputs = read_varint(transaction_as_byte_stream)
        inputs = []
        for _ in range(number_of_inputs):
            inputs.append(CTxIn.parse_transaction_input(transaction_as_byte_stream))
        number_of_outputs = read_varint(transaction_as_byte_stream)        
        outputs = []
        for _ in range(number_of_outputs):
            outputs.append(CTxOut.parse_transaction_output(transaction_as_byte_stream))
        locktime = little_endian_to_int(transaction_as_byte_stream.read(4))

        return cls(version, inputs, outputs, locktime, is_testnet=is_testnet, is_segwit=is_segwit)
    

    def serialize_transaction(self):
        transaction = int_to_little_endian(self.version, 4)
        transaction += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            transaction += tx_in.serialize_transaction_input()
        transaction += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            transaction += tx_out.serialize_transaction_output()
        transaction += int_to_little_endian(self.locktime, 4)

        return transaction
    

    def get_fee(self) -> int:
        input_sum = 0
        output_sum = 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.get_value(self.is_testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum
    

    #def verify_transaction(self) -> bool:
    #    if self.get_fee() < 0:
    #        return False
    #    for tx_in in self.tx_ins:
    #        tx_in_script_pubkey = tx_in.get_script_pubkey()

















    #    return True
        
class CTxIn:
    def __init__(self, previous_transaction_id: bytes, previous_transaction_index: int, script_sig: "Script" = None, sequence: int = 0xffffffff):
        self.previous_transaction_id = previous_transaction_id
        self.previous_transaction_index = previous_transaction_index
        self.script_sig = script_sig
        self.sequence = sequence

    
    @classmethod
    def parse_transaction_input(cls, transaction_input_as_byte_stream: BytesIO) -> "CTxIn":
        previous_transaction_id = transaction_input_as_byte_stream.read(32)[::-1]
        previous_transaction_index = little_endian_to_int(transaction_input_as_byte_stream.read(4))
        script_sig = Script.parse_script(transaction_input_as_byte_stream)
        sequence = little_endian_to_int(transaction_input_as_byte_stream.read(4))

        return cls(previous_transaction_id, previous_transaction_index, script_sig, sequence)


    def serialize_transaction_input(self) -> bytes:
        transaction_input = self.previous_transaction_id[::-1]
        transaction_input += int_to_little_endian(self.previous_transaction_index, 4)
        transaction_input += self.script_sig.serialize_script()
        transaction_input += int_to_little_endian(self.sequence, 4)
        return transaction_input

    
    def fetch_tx(self, is_testnet: bool=False):
        return TxFetcher.fetch(self.previous_transaction_id.hex(), testnet=is_testnet)
    

    def get_value(self, is_testnet: bool = False) -> int:
        tx = TxFetcher.fetch(self.previous_transaction_id.hex(), testnet=is_testnet)
        return tx.tx_outs[self.previous_transaction_index].amount
    

    def get_script_pubkey(self, is_testnet: bool = False) -> "Script":
        tx = TxFetcher.fetch(self.previous_transaction_id.hex(), testnet=is_testnet)
        return tx.tx_outs[self.previous_transaction_index].script_pubkey

class CTxOut:
    def __init__(self, amount: int, script_pubkey: "Script"):
        self.amount = amount
        self.script_pubkey = script_pubkey
    
    @classmethod
    def parse_transaction_output(cls, transaction_output_as_byte_stream: BytesIO):
        amount = little_endian_to_int(transaction_output_as_byte_stream.read(8))
        script_pubkey = Script.parse_script(transaction_output_as_byte_stream)

        return cls(amount, script_pubkey)

    def serialize_transaction_output(self):
        transaction_output = int_to_little_endian(self.amount, 8)
        transaction_output += self.script_pubkey.serialize_script()

        return transaction_output

class TxFetcher:
    cache = {}
    
    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://blockstream.info/testnet/api'
        else:
            return 'https://blockstream.info/api'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}/hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            tx = CTx.parse_transaction(BytesIO(raw), is_testnet=testnet)
            # make sure the tx we got matches to the hash we requested
            if tx.is_segwit:
                computed = tx.id()
            else:
                computed = hash256(raw)[::-1].hex()
            if computed != tx_id:
                raise RuntimeError('server lied: {} vs {}'.format(computed, tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            cls.cache[k] = CTx.parse_transaction(BytesIO(bytes.fromhex(raw_hex)))

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)