import json
import requests
from io import BytesIO

from src.helper import little_endian_to_int, read_varint, int_to_little_endian, encode_varint, SIGHASH_ALL
from src.crypto import hash256, hash160
from src.script import Script, p2pk_script, p2ms_script, p2sh_script, p2pkh_script
from src.ecdsa import Secp256k1, PrivateKey


class CTx:
    def __init__(self, version: int, tx_ins: list["CTxIn"], tx_outs: list["CTxOut"], locktime: int, is_testnet: bool, is_segwit:bool, marker: bytes = b'\x00', flag: bytes = b'\x01'):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.is_testnet = is_testnet
        self.is_segwit = is_segwit
        self.marker = marker
        self.flag = flag

    
    def id(self):
        return hash256(self.serialize_transaction_legacy())[::-1]
    

    @classmethod
    def parse_transaction(cls, transaction_as_byte_stream: BytesIO, is_testnet: bool = False) -> "CTx":
        transaction_as_byte_stream.seek(4, 1)
        if transaction_as_byte_stream.read(1) == b"\00":
            parsed_tx = cls.parse_transaction_segwit
        else:
            parsed_tx = cls.parse_transaction_legacy
        transaction_as_byte_stream.seek(-5, 1)
        
        return parsed_tx(transaction_as_byte_stream, is_testnet=is_testnet)


    @classmethod
    def parse_transaction_legacy(cls, transaction_as_byte_stream: BytesIO, is_testnet: bool = False) -> "CTx":
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

        return cls(version, inputs, outputs, locktime, is_testnet=is_testnet, is_segwit=False)
    

    @classmethod
    def parse_transaction_segwit(cls, transaction_as_byte_stream: BytesIO, is_testnet: bool = False) -> "CTx":
        version = little_endian_to_int(transaction_as_byte_stream.read(4))
        marker = transaction_as_byte_stream.read(1)
        flag = transaction_as_byte_stream.read(1)
        number_of_inputs = read_varint(transaction_as_byte_stream)
        inputs = []
        for _ in range(number_of_inputs):
            inputs.append(CTxIn.parse_transaction_input(transaction_as_byte_stream))
        number_of_outputs = read_varint(transaction_as_byte_stream)        
        outputs = []
        for _ in range(number_of_outputs):
            outputs.append(CTxOut.parse_transaction_output(transaction_as_byte_stream))
        #now the witness data stack
        for tx_input in inputs:
            num_witness_data = read_varint(transaction_as_byte_stream)
            items = []
            for _ in range(num_witness_data):
                item_length = read_varint(transaction_as_byte_stream)
                if item_length == 0:
                    items.append(0)
                else:
                    items.append(transaction_as_byte_stream.read(item_length))
            tx_input.witness = items
        locktime = little_endian_to_int(transaction_as_byte_stream.read(4))

        return cls(version, inputs, outputs, locktime, is_testnet=is_testnet, is_segwit=True, marker=marker, flag=flag)
    

    def serialize_transaction(self):
        if self.is_segwit:
            return self.serialize_transaction_segwit()
        else:
            return self.serialize_transaction_legacy()
    

    def serialize_transaction_legacy(self):
        transaction = int_to_little_endian(self.version, 4)
        transaction += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            transaction += tx_in.serialize_transaction_input()
        transaction += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            transaction += tx_out.serialize_transaction_output()
        transaction += int_to_little_endian(self.locktime, 4)

        return transaction


    def serialize_transaction_segwit(self):
        transaction = int_to_little_endian(self.version, 4)
        transaction += self.marker
        transaction += self.flag
        transaction += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            transaction += tx_in.serialize_transaction_input()
        transaction += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            transaction += tx_out.serialize_transaction_output()
        #now the witness stack
        for tx_in in self.tx_ins:
            transaction += int_to_little_endian(len(tx_in.witness), 1)
            for item in tx_in.witness:
                if isinstance(item, int):
                    transaction += int_to_little_endian(item, 1)
                else:
                    transaction += encode_varint(len(item)) + item           

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
    

    def get_sig_hash_for_legacy_transaction(self, input_index: int, previous_script_pubkey: "Script" = None) -> int:
        data = int_to_little_endian(self.version, 4)
        data += encode_varint(len(self.tx_ins))

        for index, tx_in in enumerate(self.tx_ins):
            if index == input_index:
                if previous_script_pubkey:
                    script_sig = previous_script_pubkey
                else:
                    script_sig = tx_in.get_script_pubkey(self.is_testnet)
            else:
                script_sig = None

            data += CTxIn(
                previous_transaction_id = tx_in.previous_transaction_id,
                previous_transaction_index = tx_in.previous_transaction_index,
                script_sig = script_sig,
                sequence = tx_in.sequence).serialize_transaction_input()
        
        data += encode_varint(len(self.tx_outs))

        for tx_out in self.tx_outs:
            data += tx_out.serialize_transaction_output()
        
        data += int_to_little_endian(self.locktime, 4)
        data += int_to_little_endian(SIGHASH_ALL, 4)

        return int.from_bytes(hash256(data), "big")
    

    def hash_prevouts(self):
        all_prevouts = b''
        for tx_in in self.tx_ins:
            all_prevouts += tx_in.previous_transaction_id[::-1] + int_to_little_endian(tx_in.previous_transaction_index, 4)
        hash_prevouts = hash256(all_prevouts)
        return hash_prevouts


    def hash_sequence(self):
        all_prev_sequence = b''
        for tx_in in self.tx_ins:
            all_prev_sequence += int_to_little_endian(tx_in.sequence, 4)
        hash_prev_sequence = hash256(all_prev_sequence)
        return hash_prev_sequence
    

    def hash_outputs(self):
        all_outputs = b''
        for tx_out in self.tx_outs:
            all_outputs += tx_out.serialize_transaction_output()
        hash_outputs = hash256(all_outputs)
        return hash_outputs
            

    def get_sig_hash_for_segwit_transaction(self, input_index: int, input_amount: int, script_pubkey: "Script" = None) -> int:
        """
        generating sig hash according to BIP143
            1. nVersion of the transaction (4-byte little endian)                   check
            2. hashPrevouts (32-byte hash)                                          check
            3. hashSequence (32-byte hash)                                          check
            4. outpoint (32-byte hash + 4-byte little endian)                       check -> tx_id und tx_index des segwit inputs
            5. scriptCode of the input (serialized as scripts inside CTxOuts)       check
            6. value of the output spent by this input (8-byte little endian)       check   
            7. nSequence of the input (4-byte little endian)                        check
            8. hashOutputs (32-byte hash)                                           check
            9. nLocktime of the transaction (4-byte little endian)                  check
            10. sighash type of the signature (4-byte little endian)                check
        """
        tx_in = self.tx_ins[input_index]
        
        data = int_to_little_endian(self.version, 4)
        data += self.hash_prevouts()
        data += self.hash_sequence()
        data += tx_in.previous_transaction_id[::-1] + int_to_little_endian(tx_in.previous_transaction_index, 4)        
        if script_pubkey is not None:
            if isinstance(script_pubkey, Script):
                if script_pubkey.serialize_script()[1] == 0 and len(script_pubkey.serialize_script()[3:]) == 20:
                    script_code = Script([0x19, 0x76, 0xa9, script_pubkey.serialize_script()[3:], 0x88, 0xac]).serialize_script()[1:]
            else:
                script_code = Script([0x19, 0x76, 0xa9, bytes.fromhex(script_pubkey[4:]), 0x88, 0xac]).serialize_script()[1:]
        data += script_code
        data += int_to_little_endian(input_amount, 8)
        data += int_to_little_endian(tx_in.sequence, 4)
        data += self.hash_outputs()
        data += int_to_little_endian(self.locktime, 4)
        data += int_to_little_endian(SIGHASH_ALL, 4)

        return int.from_bytes(hash256(data), 'big')


    def sign_transaction(self, input_index: int, private_keys: list[int], previous_script_pubkey: "Script" = None, number_pub_keys_required: int = 1, number_pub_keys_available: int = 1, redeem_script: "Script" = None, input_amount: int = 0):
        public_keys_sec = []
        for private_key in private_keys:
            public_keys_sec.append(PrivateKey(private_key).get_public_key().sec_format())

        if previous_script_pubkey is not None:
            if previous_script_pubkey == p2sh_script(hash160(bytes.fromhex(p2ms_script(public_keys_sec, number_pub_keys_required, number_pub_keys_available).serialize_script().hex()[2:]))):
                data_to_sign = self.get_sig_hash_for_legacy_transaction(input_index, previous_script_pubkey=redeem_script)
            elif previous_script_pubkey.serialize_script()[1] == 0 and len(previous_script_pubkey.serialize_script()[3:]) == 20:
                data_to_sign = self.get_sig_hash_for_segwit_transaction(input_index, input_amount, previous_script_pubkey)
            else:
                data_to_sign = self.get_sig_hash_for_legacy_transaction(input_index, previous_script_pubkey=previous_script_pubkey)    
        else:
            data_to_sign = self.get_sig_hash_for_legacy_transaction(input_index, previous_script_pubkey=previous_script_pubkey)
        
        der_signatures_with_sighash = []
        
        for private_key in private_keys:
            signature = Secp256k1().sign_data(private_key, data_to_sign)        
            der_signature = signature.der()
            der_signatures_with_sighash.append(der_signature + SIGHASH_ALL.to_bytes(1, "big"))
            
        
        for index, public_key_sec in enumerate(public_keys_sec):
            if previous_script_pubkey is not None:
                if previous_script_pubkey == p2pk_script(public_key_sec):
                    script_sig = Script([der_signatures_with_sighash[index]])
                elif previous_script_pubkey == p2ms_script(public_keys_sec, number_pub_keys_required, number_pub_keys_available):
                    der_signatures_with_sighash_new = [bytes(0x0)] + der_signatures_with_sighash
                    script_sig = Script(der_signatures_with_sighash_new)
                elif previous_script_pubkey == p2sh_script(hash160(bytes.fromhex(p2ms_script(public_keys_sec, number_pub_keys_required, number_pub_keys_available).serialize_script().hex()[2:]))):
                    der_signatures_with_sighash_new = [bytes(0x0)] + der_signatures_with_sighash + [bytes.fromhex(redeem_script.serialize_script().hex()[2:])]
                    script_sig = Script(der_signatures_with_sighash_new)
                elif previous_script_pubkey.serialize_script()[1] == 0 and len(previous_script_pubkey.serialize_script()[3:]) == 20:
                    script_sig = Script([])
                    self.tx_ins[input_index].witness = der_signatures_with_sighash + [public_key_sec]
                else:
                    script_sig = Script([der_signatures_with_sighash[index], public_key_sec])
            else:
                script_sig = Script([der_signatures_with_sighash[index], public_key_sec])
    
        self.tx_ins[input_index].script_sig = script_sig
    
        
class CTxIn:
    def __init__(self, previous_transaction_id: bytes, previous_transaction_index: int, script_sig: "Script" = None, sequence: int = 0xffffffff, witness: list = []):
        self.previous_transaction_id = previous_transaction_id
        self.previous_transaction_index = previous_transaction_index
        self.script_sig = script_sig
        self.sequence = sequence
        self.witness = witness

    
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