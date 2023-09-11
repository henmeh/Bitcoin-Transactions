import hashlib
import base58
from Crypto.Hash import RIPEMD160
import bech32ref
import random

class ECDSA:

    def __init__(self, curve):
        if curve == "secp256k1":
            #y² = x³ +a*x + b mod p
            self.a = 0
            self.b = 7
            self.p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
            self.max_points = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            self.max_points_int: int = int(self.max_points, 16)
            self.generator_point = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)

    
    def gcdExtended(self, a, b):

        if a == 0 :
            return b,0,1
                
        gcd,x1,y1 = self.gcdExtended(b%a, a)
        x = y1 - (b//a) * x1
        y = x1
        
        return gcd,x,y


    def ec_addition(self, P1, P2):
        
        s = ((P2[1] - P1[1]) * self.gcdExtended(self.p, (P2[0] - P1[0]))[2]) % self.p
        x = (pow(s,2) - P1[0] - P2[0]) % self.p
        y = (s * (P1[0] - x) - P1[1]) % self.p

        return (x,y)


    def ec_doubling(self, P1):
        
        s = ((3 * pow(P1[0], 2) + self.a) * self.gcdExtended(self.p, (2 * P1[1]))[2]) % self.p
        x = (pow(s, 2) - 2* P1[0]) % self.p
        y = (s * (P1[0] - x) - P1[1]) % self.p

        return (x,y)


    def ec_multiply(self, private_key: int):

        if 0 < private_key <= self.max_points_int:
            key_public = self.generator_point

            #to speed up calculations we use the double and add algorithmus
            key_priv_binary = bin(private_key)[2:]
            
            for i in range(1, len(key_priv_binary)):
                key_public = self.ec_doubling(key_public)
                if (key_priv_binary[i]=="1"):
                    key_public = self.ec_addition(key_public, self.generator_point)

        else:
            print("This is an invalid private key!")

        return (key_public[0], key_public[1])


    def sign_data(self, hash_of_data_to_sign, key_priv_int,):

        random_number = 123456789
        #random_number = random.randint(1, self.max_points_int)

        x_random_signing_point, _ = self.ec_multiply(random_number)
        r = x_random_signing_point
        s = ((int(hash_of_data_to_sign,16) + r * key_priv_int) * (self.gcdExtended(self.max_points_int, random_number)[2])) % self.max_points_int

        #use the low s value (BIP 62: Dealing with malleability)
        if (s > self.max_points_int / 2):
            s = self.max_points_int - s

        r_hex: str = r.to_bytes(32, "big").hex()
        s_hex: str = s.to_bytes(32, "big").hex()

        return (r_hex, s_hex)
    

    def verify_signature(self, hash_of_data_to_sign, s, public_key, r):

        w = self.gcdExtended(self.max_points_int, s)[2]
        u1 = (w * hash_of_data_to_sign) % self.max_points_int
        u2 = (w * r) % self.max_points_int
        xu1, yu1 = self.ec_multiply(u1)
        xu2, yu2 = self.ec_multiply(u2)
        x, y = self.ec_addition((xu1, yu1), (xu2, yu2))

        return x == r % self.max_points_int


class Bitcoin:

    def __init__(self):
        self.hash = Hashes()
        self.curve = ECDSA("secp256k1")


    def base58_address_to_pubkey_hash(self, base58_address: str):
    
        decoded = base58.b58decode_check(base58_address).hex()[2:]

        return decoded

    
    def pubkey_to_base58_address(self, pubKey: str, chain: str, datatype_to_encode: str, do_hash_pub_key: bool):
        
        prefixes = {
            "mainnet": {
                "p2pkh": "00",
                "p2sh": "05",
                "wif_private_key": "80",
                "extended_private_key": "0488ADE4",
                "extended_public_key": "0484B21E",
            },

            "testnet": {
                "p2pkh": "6F",
                "p2sh": "C4",
                "wif_private_key": "EF",
                "extended_private_key": "04358394",
                "extended_public_key": "043587CF",
            },
        }
        
        prefix = prefixes[chain][datatype_to_encode]     
        
        hash = Hashes()

        public_key_hash = pubKey if do_hash_pub_key == False else hash.hash160(hash.sha256(pubKey))
        prefix_and_public_key_hash = f"{prefix}{public_key_hash}"
        checksum = hash.hash256(prefix_and_public_key_hash)[0:8]
        base58_adress_input = bytes.fromhex(f"{prefix_and_public_key_hash}{checksum}")
        base58_compressed_address = base58.b58encode(base58_adress_input)

        return base58_compressed_address
    

    def calculate_txid_from_raw_transaction(self, rawtransaction: str):

        hash = Hashes()

        return hash.hash256(rawtransaction)

       
    def get_bech32_address(self, data, hrp):

        data_in_bytes = bytes.fromhex(data)
        witness_version = 0
        bech32_address = bech32ref.encode(hrp, witness_version, data_in_bytes)

        return bech32_address


    def bech32_address_to_script_pubkey(self, hrp: str, address: str):

        witver, witprog = bech32ref.decode(hrp, address)
        script_pubkey = bytes([witver + 0x50 if witver else 0, len(witprog)] + witprog)

        return script_pubkey.hex()
    

    def create_raw_transaction(self, tx_id: str, vout: str, scriptSig: str, amount_satoshi: int, scriptPubKey: str, is_segWit: bool = True):

        tx_id_little_endian: str = convert_endianes(tx_id)
        vout_big_endian_hex: str = int(vout).to_bytes(4, "big").hex()
        vout_little_endian: str = convert_endianes(vout_big_endian_hex)
        amount_satoshi_hex: str = hex(amount_satoshi)[2:]
        amount_satoshi_hex_little_endian_with_all_bytes: str = int(amount_satoshi_hex,16).to_bytes(8, "little").hex()

        if is_segWit:
            raw_transaction_dict = {
            "version": '01000000',
            "marker+flag": '0001',
            "input_count": '01',
            "inputs": [
                {
                    "txid": f'{tx_id_little_endian}',
                    "vout": f'{vout_little_endian}',
                    "scriptSig": '00',
                    "sequence": 'feffffff',
                },
            ],
            "output_count": '01',
            "outputs": [
                {
                    "amount": f'{amount_satoshi_hex_little_endian_with_all_bytes}',
                    "scriptPubKey": f'{hex(len(scriptPubKey) // 2)[2:]}{scriptPubKey}'
                },
            ],
            "witness": f'{scriptSig}',
            "locktime": '00000000'
            }

        else:
            raw_transaction_dict = {
            "version": '01000000',
            "input_count": '01',
            "inputs": [
                {
                    "txid": f'{tx_id_little_endian}',
                    "vout": f'{vout_little_endian}',
                    "scriptSig": f'{hex(len(scriptSig) // 2)[2:]}{scriptSig}',
                    "sequence": '00000000',
                },
            ],
            "output_count": '01',
            "outputs": [
                {
                    "amount": f'{amount_satoshi_hex_little_endian_with_all_bytes}',
                    "scriptPubKey": f'{hex(len(scriptPubKey) // 2)[2:]}{scriptPubKey}'
                },
            ],
            "locktime": '00000000'
            }

        raw_transaction = ""
        for key, value in raw_transaction_dict.items():
            if type(value) == str:
                raw_transaction += value
            if type(value) == list:
                for item in range(0, len(value)):
                    for key1, value1 in value[item].items():
                        raw_transaction += value1
    
        return (raw_transaction_dict, raw_transaction)


    def calculate_p2sh_scriptPubKey(self, secret: str):

        secret_hex: str = convert_string_to_hex(secret)
        original_script: str = f"{hex(len(secret_hex) // 2)}{secret_hex + '87'}"[2:]
        original_script_hash160: str = self.hash.hash160(original_script)
        p2sh_script: str = f"a9{hex(len(original_script_hash160) // 2)[2:]}{original_script_hash160}87"   

        return (original_script, p2sh_script, secret_hex)
    

    def calculate_p2wsh_scriptPubKey(self, secret: str):

        secret_hex: str = convert_string_to_hex(secret)
        original_script: str = f"{hex(len(secret_hex) // 2)}{secret_hex + '87'}"[2:]
        original_script_sha256: str = self.hash.sha256(original_script)
        p2wsh_script: str = f"00{hex(len(original_script_sha256) // 2)[2:]}{original_script_sha256}"   

        return (original_script, p2wsh_script, secret_hex)
    

    def calculate_p2pkh_scriptSig(self, raw_transaction: str, private_key_wif: str, sighash_flag_hex: str):

        _, compressed_public_key_hex, private_key_int = self.calculate_public_key(private_key_wif, "wif")
        compressed_pubKey_hex_length: str = hex(len(compressed_public_key_hex)//2)[2:]
        
        tx_to_spent_hex: str= raw_transaction+"01000000"
        tx_to_spent_hash: str = self.hash.hash256(tx_to_spent_hex)

        r_hex, s_hex = self.curve.sign_data(tx_to_spent_hash, private_key_int)        
        
        signature_hex: str = f"02{hex(len(f'{r_hex}')//2)[2:]}{r_hex}02{hex(len(f'{s_hex}')//2)[2:]}{s_hex}"
        signature_marker_hex: str = "30"
        signature_hex_length: str = hex(len(signature_hex)//2)[2:]
        signature_and_sighash_hex_length: str = hex(len(signature_marker_hex+signature_hex_length+signature_hex+sighash_flag_hex)//2)[2:]

        script_sig_hex: str = signature_and_sighash_hex_length+signature_marker_hex+signature_hex_length+signature_hex+sighash_flag_hex+compressed_pubKey_hex_length+compressed_public_key_hex

        return script_sig_hex


    def calculate_p2sh_scriptSig(self, secret: str):

        original_script, p2sh_script, secret_hex = self.calculate_p2sh_scriptPubKey(secret)
        original_script_length_hex = hex(len(original_script) // 2)[2:]
        secret_hex_length_hex = hex(len(secret_hex) // 2)[2:]

        script_sig = f"{secret_hex_length_hex}{secret_hex}{original_script_length_hex}{original_script}"

        return script_sig

    
    def calculate_p2wpkh_witness_data(self, transaction, signing_data):
       
        #Input Data
        prevouts = ""
        sequences = ""
        script_code = ""
        input_amounts = ""
        input_sequences = ""

        for input in range(len(transaction['tx_inputs']['tx_input_ids'])):
            vout: str = int(transaction['tx_inputs']['tx_input_vouts'][input]).to_bytes(4, "big").hex()
            vout: str = convert_endianes(vout)
            prevouts = prevouts + f"{convert_endianes(transaction['tx_inputs']['tx_input_ids'][input])}{vout}"
            sequences = sequences + f"{transaction['tx_inputs']['tx_input_sequences'][input]}"
            pubkey_hash = self.bech32_address_to_script_pubkey("bcrt", transaction['tx_inputs']['tx_input_address'][input])[4:]
            script_code = script_code + f"1976a914{pubkey_hash}88ac"
            input_amounts = input_amounts + f"{format_satoshi_amounts(transaction['tx_inputs']['tx_input_amounts'][input])}"
            input_sequences = input_sequences + f"{transaction['tx_inputs']['tx_input_sequences'][input]}"

        #1 version and hash_prevouts
        hash_prevouts = self.hash.hash256(prevouts)
        print(f"Hash prevouts: {hash_prevouts}")

        #2 hash_sequence 
        hash_sequence = self.hash.hash256(sequences)
        print(f"Hash sequences: {hash_sequence}")

        print(f"Outpoint: {prevouts}")
        print(f"Script code: {script_code}")
        
        #4 Output Data
        outputs = ""
        for output in range(len((transaction['tx_outputs']['tx_output_amounts']))):
            outputs = outputs + f"{format_satoshi_amounts(transaction['tx_outputs']['tx_output_amounts'][output])}{transaction['tx_outputs']['tx_output_scriptPubKeys'][output]}"

        hash_outputs = self.hash.hash256(outputs)
        print(f"Hash outputs: {hash_outputs}")
        print(f"Outputs: {outputs}")
               
        #print(f"Input amounts: {input_amounts}")

        hash_preimage = f"{transaction['version']}{hash_prevouts}{hash_sequence}{prevouts}{script_code}{input_amounts}{input_sequences}{hash_outputs}{transaction['locktime']}{transaction['sig_hash_flag'].to_bytes(1, 'little').hex()}" 
        print(f"Hash preimage: {hash_preimage}")

        data_to_sign = self.hash.hash256(hash_preimage)
        print(f"Data to sign: {data_to_sign}")
                
        #9 signing
        _, compressed_public_key_hex, private_key_int = self.calculate_public_key(signing_data["private_key"], signing_data["private_key_format"])
        print(f"Compressed Public Key: {compressed_public_key_hex}")
        print(f"Private Key int: {private_key_int}")
        print(f"Private Key hex: {hex(private_key_int)[2:]}")
        r_hex, s_hex = self.curve.sign_data(data_to_sign, private_key_int)        

        signature_hex: str = f"02{hex(len(f'{r_hex}')//2)[2:]}{r_hex}02{hex(len(f'{s_hex}')//2)[2:]}{s_hex}"
        signature_marker_hex: str = "30"
        signature_hex_length: str = hex(len(signature_hex) // 2)[2:]
        signature_and_sighash_hex_length: str = hex(len(signature_marker_hex+signature_hex_length+signature_hex+transaction['sig_hash_flag'].to_bytes(1, 'little').hex()) // 2)[2:]

        compressed_pubKey_hex_length: str = hex(len(compressed_public_key_hex)//2)[2:]
          
        witness_part1: str = f"{signature_and_sighash_hex_length}{signature_marker_hex}{signature_hex_length}{signature_hex}{transaction['sig_hash_flag'].to_bytes(1, 'little').hex()}"
        witness_part2: str = f"{compressed_pubKey_hex_length}{compressed_public_key_hex}"

        witness_stack = []
        witness_stack.append(f"{witness_part1}")
        witness_stack.append(f"{witness_part2}")

        witness_stack_height = f"0{len(witness_stack)}"

        witness_data = f"{witness_stack_height}"

        for i in witness_stack:
            witness_data += i

        print(f"Witness_stack: {witness_data}")
        
        return witness_data 
    
    """
    def calculate_p2wpkh_witness_data(self, tx_inputs: dict, tx_outputs: dict, version: str, outpoint: str, locktime: str, sig_hash_flag: int, private_key_wif: str, public_key_sender: str):
       
        #Input Data
        prevouts = ""
        sequences = ""
        for transaction in range(len(tx_inputs["tx_ids"])):
            vout: str = int(tx_inputs["vouts"][transaction]).to_bytes(4, "big").hex()
            vout: str = convert_endianes(vout)
            prevouts = prevouts + f"{convert_endianes(tx_inputs['tx_ids'][transaction])}{vout}"
        
            sequences = sequences + f"{tx_inputs['sequences'][transaction]}"

        #1 version and hash_prevouts
        hash_prevouts = self.hash.hash256(prevouts)
        #print(f"Hash of prevouts: {hash_prevouts}")

        #2 hash_sequence 
        hash_sequence = self.hash.hash256(sequences)
        #print(f"Hash of sequences: {hash_sequence}")
      
        #Output Data
        outputs = ""
        for output in range(len(tx_outputs['amounts'])):
            outputs = outputs + f"{format_satoshi_amounts(tx_outputs['amounts'][output])}{tx_outputs['scriptPubKeys'][output]}"

        hash_outputs = self.hash.hash256(outputs)
        #print(f"Hash of outputs: {hash_outputs}")
        #print(f"Outpoint: {outpoint}")

        #4 scriptCode of the input for P2WPKH it is 1976a914 <pubkey hash> 88ac
        #pubic key of sender
        pubkey_hash = self.hash.dhash160(public_key_sender)
        #pubkey_hash = self.bech32_address_to_script_pubkey(hrp_address_sender_segwit_transaction, address_sender_segwit_transaction)[4:]
        script_code = f"1976a914{pubkey_hash}88ac"
        #print(f"Script code: {script_code}")

        input_amounts = ""
        for amount in range(len(tx_inputs["input_amounts_of_segwit_inputs"])):
            input_amounts = input_amounts + f"{format_satoshi_amounts(tx_inputs['input_amounts_of_segwit_inputs'][amount])}"

        segwit_sequences = ""
        for sequence in range(len(tx_inputs["sequences_of_segwit_inputs"])):
            input_amounts = input_amounts + f"{tx_inputs['sequences_of_segwit_inputs'][sequence]}"

        #print(f"Input amounts: {input_amounts}")

        hash_preimage = f"{version}{hash_prevouts}{hash_sequence}{outpoint}{script_code}{input_amounts}{segwit_sequences}{hash_outputs}{locktime}{sig_hash_flag.to_bytes(4, 'little').hex()}"
        print(hash_preimage)
        #print(hash_preimage == "0200000099197e88ff743aff3e453e3a7b745abd31937ccbd56f96a179266eba786833e682a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be89cb872539fbe1bc0b9c5562195095f3f35e6e13919259956c6263c9bd53b20b7010000001976a914594c2e3da92d1904f7e7c856220f8cae5efb556488ac5424000000000000fffffffff3ae23c3fd63a2e0479888f95c7a8ab221b20add6ac819e9d8953edd1a0cd9240000000001000000")
        #print(hash_preimage == "0200000099197e88ff743aff3e453e3a7b745abd31937ccbd56f96a179266eba786833e682a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be89cb872539fbe1bc0b9c5562195095f3f35e6e13919259956c6263c9bd53b20b7010000001976a914594c2e3da92d1904f7e7c856220f8cae5efb556488ac5424000000000000fffffffff3ae23c3fd63a2e0479888f95c7a8ab221b20add6ac819e9d8953edd1a0cd9240000000001000000")

        data_to_sign = self.hash.hash256(hash_preimage)
        print(f"Data to sign: {data_to_sign}")
                
        #9 signing
        _, compressed_public_key_hex, private_key_int = self.calculate_public_key(private_key_wif, "wif")
        r_hex, s_hex = self.curve.sign_data(data_to_sign, private_key_int)        

        signature_hex: str = f"02{hex(len(f'{r_hex}')//2)[2:]}{r_hex}02{hex(len(f'{s_hex}')//2)[2:]}{s_hex}"
        signature_marker_hex: str = "30"
        signature_hex_length: str = hex(len(signature_hex) // 2)[2:]
        signature_and_sighash_hex_length: str = hex(len(signature_marker_hex+signature_hex_length+signature_hex+sig_hash_flag.to_bytes(1, 'little').hex()) // 2)[2:]

        compressed_pubKey_hex_length: str = hex(len(compressed_public_key_hex)//2)[2:]
          
        witness_part1: str = f"{signature_and_sighash_hex_length}{signature_marker_hex}{signature_hex_length}{signature_hex}{sig_hash_flag.to_bytes(1, 'little').hex()}"
        witness_part2: str = f"{compressed_pubKey_hex_length}{compressed_public_key_hex}"

        witness_stack = []
        witness_stack.append(f"{witness_part1}")
        witness_stack.append(f"{witness_part2}")

        witness_stack_height = f"0{len(witness_stack)}"

        witness_data = f"{witness_stack_height}"

        for i in witness_stack:
            witness_data += i
        
        
        return witness_data
    """

    def calculate_p2wsh_witness_data(self, secret: str):
        
        original_script, p2wsh_script, secret_hex = self.calculate_p2wsh_scriptPubKey(secret)
        original_script_length_hex = hex(len(original_script) // 2)[2:]
        secret_hex_length_hex = hex(len(secret_hex) // 2)[2:]
    
        witness_stack = []
        witness_stack.append(f"{secret_hex_length_hex}{secret_hex}")
        witness_stack.append(f"{original_script_length_hex}{original_script}")

        witness_stack_height = f"0{len(witness_stack)}"

        witness_data = f"{witness_stack_height}"

        for i in witness_stack:
            witness_data += i
        
        return witness_data


    def calculate_p2pkh_scriptPubKey(self, address: str):

        public_key_hash: str = self.base58_address_to_pubkey_hash(address) 

        #OP_DUP OP_HASH160 PKH OP_EQUALVERIFY OP_CHECKSIG
        p2pkh_script: str = f"76a9{hex(len(public_key_hash) // 2)[2:]}{public_key_hash}88ac"

        return p2pkh_script
     

    def calculate_public_key(self, private_key: str, private_key_format: str):

        if private_key_format == "wif":
            
            private_key_bytes: bytes = base58.b58decode_check(private_key)
            private_key_hex: str = private_key_bytes.hex()[2:-2]
            private_key_int: int = int(private_key_hex, 16)

        elif private_key_format == "int":

            private_key_int = private_key

        public_key_int: str = self.curve.ec_multiply(private_key_int)
        uncompressed_public_key = (f"04{hex(public_key_int[0])[2:]}{hex(public_key_int[1])[2:]}")
        
        if (int(hex(public_key_int[1])[2:], 16) % 2 == 0):
            compressed_public_key: str = f"02{hex(public_key_int[0])[2:]}"
        else:
            compressed_public_key: str = f"03{hex(public_key_int[0])[2:]}" #verstehe ich noch nicht wirklich warum bei p2sh 030{hex(public_key_int[0])[2:]} gilt???

        return (uncompressed_public_key, compressed_public_key, private_key_int)
    

class Hashes:

    def __init__(self):
        pass


    def hash160(self, data):

        data_in_bytes = bytes.fromhex(data)

        #sha256= hashlib.sha256(data_in_bytes).digest() 

        hash160 = RIPEMD160.new()
        hash160.update(data_in_bytes)

        return hash160.hexdigest()


    def dhash160(self, data):

        data_in_bytes = bytes.fromhex(data)

        sha256= hashlib.sha256(data_in_bytes).digest() 

        hash160 = RIPEMD160.new()
        hash160.update(sha256)

        return hash160.hexdigest()


    def hash256(self, data):

        data_in_bytes = bytes.fromhex(data)

        hash256 = hashlib.sha256(hashlib.sha256(data_in_bytes).digest()).hexdigest()

        return hash256


    def sha256(self, data):

        data_in_bytes = bytes.fromhex(data)

        sha256 = hashlib.sha256(data_in_bytes).hexdigest()

        return sha256




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