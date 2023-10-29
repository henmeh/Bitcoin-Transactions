# Tx is a class to parse and serialize bitcoin transactions
from format_converter import Converter
from helper_functions import read_varint, encode_varint, SIGHASH_ALL
from script import Script, p2pkh_script
from hash_calculation import Hashes
from bitcoin_transaction_helpers import ECDSA, Bitcoin


converter = Converter()
hash = Hashes()
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()

class Tx:

    def __init__(self, version: int, tx_ins: list, tx_outs: list, locktime: int, is_testnet: bool=False, is_segwit: bool=False) -> "Tx":
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.is_testnet = is_testnet
        self.is_segwit = is_segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None
    

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
        return hash.hash256(self.serialize_legacy())[::-1]


    @classmethod
    def parse(cls, stream: bytes, is_testnet: bool=False) -> "Tx":
        stream.read(4)
        if stream.read(1) == b'\x00':
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        stream.seek(-5,1)
        
        return parse_method(stream, is_testnet=is_testnet)
    

    @classmethod
    def parse_legacy(cls, stream: bytes, is_testnet: bool=False) -> "Tx":
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

        return cls(version, inputs, outputs, locktime, is_testnet=is_testnet, is_segwit=False)
    

    @classmethod
    def parse_segwit(cls, stream: bytes, is_testnet: bool=False) -> "Tx":
        version = converter.little_endian_to_int(stream.read(4))
        marker = stream.read(2)
        if marker != b'\x00\x01':  # <1>
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))
        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))
        for tx_in in inputs:
            num_items = read_varint(stream)
            items = []
            for _ in range(num_items):
                item_len = read_varint(stream)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(stream.read(item_len))
            tx_in.witness = items
        locktime = converter.little_endian_to_int(stream.read(4))

        return cls(version, inputs, outputs, locktime, is_testnet=is_testnet, is_segwit=True)


    def serialize(self) -> bytes:
        if self.is_segwit:
            return self.serialize_segwit()
        else:
            return self.serialize_legacy()
    

    def serialize_legacy(self):
        result = converter.int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += converter.int_to_little_endian(self.locktime, 4)
        return result
    

    def serialize_segwit(self):
        result = converter.int_to_little_endian(self.version, 4)
        result += b'\x00\x01'
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        for tx_in in self.tx_ins:  # <3>
            result += converter.int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if type(item) == int:
                    result += converter.int_to_little_endian(item, 1)
                else:
                    result += encode_varint(len(item)) + item
        result += converter.int_to_little_endian(self.locktime, 4)
        return result

    
    def fee(self) -> int:
        input_sum = 0
        output_sum = 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.is_testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum


    def sig_hash_legacy(self, input_index: int, redeem_script: Script=None) -> int:
        sig_hash = converter.int_to_little_endian(self.version, 4)
        sig_hash += encode_varint(len(self.tx_ins))
        for index, tx_in in enumerate(self.tx_ins):
            if index == input_index:
                if redeem_script:
                    script_sig = redeem_script
            else:
                script_sig = None
        sig_hash += TxIn(prev_tx_id=tx_in.prev_tx_id, prev_index=tx_in.prev_index, script_sig=script_sig, sequence=tx_in.sequence).serialize()
        sig_hash += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            sig_hash += tx_out.serialize()
        sig_hash += converter.int_to_little_endian(self.locktime, 4)
        sig_hash += converter.int_to_little_endian(SIGHASH_ALL, 4)
        hash256 = hash.hash256(sig_hash)
        
        return int.from_bytes(hash256, 'big')
    

    def sig_hash_segwit(self, input_index: int, redeem_script: str=None, witness_script: str=None) -> int:
        tx_in = self.tx_ins[input_index]
        sig_hash = converter.int_to_little_endian(self.version, 4)
        sig_hash += self.hash_prevouts() + self.hash_sequence()
        sig_hash += tx_in.prev_tx[::-1] + converter.int_to_little_endian(tx_in.prev_index, 4)
        if witness_script:
            script_code = witness_script.serialize()
        elif redeem_script:
            script_code = p2pkh_script(redeem_script.cmds[1]).serialize()
        else:
            script_code = p2pkh_script(tx_in.script_pubkey(self.testnet).cmds[1]).serialize()
        sig_hash += script_code
        sig_hash += converter.int_to_little_endian(tx_in.value(), 8)
        sig_hash += converter.int_to_little_endian(tx_in.sequence, 4)
        sig_hash += self.hash_outputs()
        sig_hash += converter.int_to_little_endian(self.locktime, 4)
        sig_hash += converter.int_to_little_endian(SIGHASH_ALL, 4)
        
        return int.from_bytes(hash.hash256(sig_hash), 'big')


    def hash_sequence(self) -> str:
        if self._hash_sequence is None:
            self.hash_prevouts()
        
        return self._hash_sequence


    def hash_outputs(self) -> str:
        if self._hash_outputs is None:
            all_outputs = b''
            for tx_out in self.tx_outs:
                all_outputs += tx_out.serialize()
            self._hash_outputs = hash.hash256(all_outputs)
        
        return self._hash_outputs


    def sign_input(self, input_index: int, private_key: str, redeem_script) -> bool:
        sig_hash = self.sig_hash_legacy(input_index, redeem_script)
        r, s = curve.sign_data(sig_hash, private_key)
        der = curve.der(r, s)
        signature = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = curve.calculate_public_key(private_key)
        script_sig = Script([signature, sec])
        self.tx_ins[input_index].script_sig = script_sig
        
        return True
    

class TxIn:

    def __init__(self, prev_tx_id: bytes, prev_index: int, script_sig: Script=None, sequence: int=0xffffffff) -> "TxIn":
        self.prev_tx_id = prev_tx_id
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence


    def __repr__(self) -> str:
        
        return f'{self.prev_tx_id.hex()}:{self.prev_index}'


    @classmethod
    def parse(cls, stream: bytes) -> "TxIn":
        prev_tx_id = stream.read(32)[::-1]
        prev_index = converter.little_endian_to_int(stream.read(4))
        script_sig = Script.parse(stream)
        sequence = converter.little_endian_to_int(stream.read(4))
        
        return cls(prev_tx_id, prev_index, script_sig, sequence)
    

    def serialize(self) -> bytes:
        tx_in = self.prev_tx_id[::-1]
        tx_in += converter.int_to_little_endian(self.prev_index, 4)
        tx_in += self.script_sig.serialize()
        tx_in += converter.int_to_little_endian(self.sequence, 4)
        
        return tx_in


class TxOut:

    def __init__(self, amount: int, script_pubkey: bytes) -> "TxOut":
        self.amount = amount
        self.script_pubkey = script_pubkey


    def __repr__(self) -> str:

        return f'{self.amount}:{self.script_pubkey}'


    @classmethod
    def parse(cls, stream: bytes) -> "TxOut":
        amount = converter.little_endian_to_int(stream.read(8))
        script_pubkey = Script.parse(stream)
        
        return cls(amount, script_pubkey)
    

    def serialize(self) -> bytes:
        tx_out = converter.int_to_little_endian(self.amount, 8)
        tx_out += self.script_pubkey.serialize()
        
        return tx_out