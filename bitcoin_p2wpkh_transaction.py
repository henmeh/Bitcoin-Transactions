from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes, convert_endianes

# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()


def main():
    
    """
    transaction = {
        "version": "02000000",
        "tx_inputs": {
            "tx_input_ids": ["fd2fcee5dd168cf2cbb8c2d64b0fa98956ec892e7ea4526f2e54891814fecd25"],
            "tx_input_vouts": [0],
            "tx_input_sequences": ["feffffff"],
            "tx_input_amounts": [100000],
            "tx_input_pubkeys": ["tb1q7xats2uvpvysdna52c2j3p3zlnrfuhx3c4rj6n"]
        },
        "tx_outputs": {
            "tx_output_amounts": [49817, 50000],
            "tx_output_scriptPubKeys": [bitcoin.bech32_address_to_script_pubkey('tb', "tb1q65kw8v97qm6r753a7cv6hqtddcdwhtu360pjqd"), bitcoin.bech32_address_to_script_pubkey('tb', "tb1qm0r8qe0lxs8yf9tywxjtskntvdkzywsx2cacr2")]
        },
        "locktime": "56f60000",
        "sig_hash_flag": 1,
    }

    signing_data = {
        "private_key": int("8e9d4e802cecb0f703bd2d0136c3527670a79a9dc6d112ba2951ddc60c3da294", 16),
    }

    bitcoin.calculate_p2wpkh_witness_data(transaction, signing_data)
    

    transaction = {
        "version": "01000000",
        "tx_inputs": {
            "tx_input_ids": ["e498691be78f6a4abf880185a924c5e867d6b93954408e8a0b6a622ed1d93a35"],
            "tx_input_vouts": [1],
            "tx_input_sequences": ["feffffff"],
            "tx_input_amounts": [10000],
            "tx_input_address": ["bcrt1qpatwhafeqj70t7jg9r6d3nchugj7avaxc8june"]
        },
        "tx_outputs": {
            "tx_output_amounts": [9000],
            "tx_output_scriptPubKeys": [bitcoin.bech32_address_to_script_pubkey('bcrt', "bcrt1qppwq0h4x3shlzy0tr2uz7dpspesv2cjzjkyzhu")]
        },
        "locktime": "00000000",
        "sig_hash_flag": 1,
    }

    signing_data = {
        "private_key": "cMre2aLb9a2UKv7XMiRg3Qk1wqxGFR9AUQy564Uw42eD4rSkTSLe",
        "private_key_format": "wif"
    }

   
    witness_data = bitcoin.calculate_p2wpkh_witness_data(transaction, signing_data)
    print(f"Witness Data: {witness_data}")
   
    _, signed_raw_transaction = bitcoin.create_raw_transaction(transaction["tx_inputs"]["tx_input_ids"][0], transaction["tx_inputs"]["tx_input_vouts"][0], witness_data, transaction["tx_outputs"]["tx_output_amounts"][0], transaction["tx_outputs"]["tx_output_scriptPubKeys"][0], is_segWit=True)
    
    #print("-----------------------------------------------")
    print(f"Signed transaction: {signed_raw_transaction}")


    """ 
    tx_id1 = convert_endianes("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f")
    tx_id2 = convert_endianes("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a")

    tx_inputs = {
        "tx_ids": [tx_id1, tx_id2],
        "vouts": [0, 1],
        "sequences": ["eeffffff", "ffffffff"],
        "input_amounts_of_segwit_inputs": [600000000],
        "sequences_of_segwit_inputs": ["ffffffff"]
    }

    tx_outputs = {
        "amounts": [112340000, 223450000],        
        "scriptPubKeys": ["1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac", "1976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"]
    }

    version = "01000000"
    outpoint = f"{convert_endianes(tx_id2)}01000000"
    locktime = "11000000"
    sig_hash_flag = 1
    private_key_wif: str = "cQbxgcrV7pLYzi6JDpRBYgA7Tbjj2A5bifxCiMMAv1tzGibAEuRc"
    public_key_sender: str = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"

    witness_data = bitcoin.calculate_p2wpkh_witness_data(tx_inputs, tx_outputs, version, outpoint, locktime, sig_hash_flag, private_key_wif, public_key_sender)
    print(witness_data)   
    
    
    """
    tx_id1 = convert_endianes("ed204affc7519dfce341db0569687569d12b1520a91a9824531c038ad62aa9d1")
    tx_id2 = convert_endianes("9cb872539fbe1bc0b9c5562195095f3f35e6e13919259956c6263c9bd53b20b7")
    tx_id3 = convert_endianes("8012f1ec8aa9a63cf8b200c25ddae2dece42a2495cc473c1758972cfcd84d904")

    tx_inputs = {
        "tx_ids": [tx_id1, tx_id2, tx_id3],
        "vouts": [1, 1, 1],
        "sequences": ["ffffffff", "ffffffff", "ffffffff"],
        "input_amounts_of_segwit_inputs": [9300],
        "sequences_of_segwit_inputs": ["ffffffff"]
    }

    address_receiver: str = "tb1qeds7u3tgpqkttxkzdwukaj8muqgf5nqq6w05ak"
    script_pub_key_hex = bitcoin.bech32_address_to_script_pubkey('tb', address_receiver)
    
    tx_outputs = {
        "amounts": [16089269],        
        "scriptPubKeys": [script_pub_key_hex]
    }

    version = "02000000"
    outpoint = f"{convert_endianes(tx_id2)}01000000"
    locktime = "00000000"
    sig_hash_flag = 1
    private_key_wif: str = "cQbxgcrV7pLYzi6JDpRBYgA7Tbjj2A5bifxCiMMAv1tzGibAEuRc"
    public_key_sender: str = "025972A1F2532B44348501075075B31EB21C02EEF276B91DB99D30703F2081B773"

    witness_data = bitcoin.calculate_p2wpkh_witness_data(tx_inputs, tx_outputs, version, outpoint, locktime, sig_hash_flag, private_key_wif, public_key_sender)
    print(witness_data)

    """

if __name__ == "__main__":
    main()
