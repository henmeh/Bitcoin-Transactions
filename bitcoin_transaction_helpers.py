import base58
import bech32ref
from ecdsa_calculation import ECDSA
from hash_calculation import Hashes
from format_converter import Converter



class Bitcoin:

    def __init__(self):
        self.hash = Hashes()
        self.curve = ECDSA("secp256k1")
        self.converter = Converter()


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