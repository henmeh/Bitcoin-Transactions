from bitcoin_transaction_helpers import ECDSA, Hashes, Bitcoin
from helper_functions import Converter
from script import Script, p2wsh_script
from transaction import Tx, TxIn, TxOut

# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()
converter = Converter()


def main():

    version = 1
    tx_id_to_spent = '0529dc15a75d7fe4473a323c7d0236d8801b3fc5945f97e494895d8161ce36e3'
    tx_index_to_spent = 1
    amount_to_spent = 9000
    locktime = 0xffffffff

    # now we build the script we want to sent the funds   
    secret = "this is base58 yall"
    secret_hex = converter.convert_string_to_hex(secret)
    original_script = Script([bytes.fromhex(secret_hex), 0x87])
    original_script_hex = original_script.serialize().hex()[2:] #serialize will give back also the length of the total script, but this is not part of the hashing data  
    original_script_sha256 = hash.sha256(bytes.fromhex(original_script_hex))
    
    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)

    # step 2: create the transaction output 
    p2wsh = p2wsh_script(original_script_sha256)
    transaction_output = TxOut(amount_to_spent, p2wsh)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    print(raw_transaction.serialize().hex())

    # step 3: sign the sig hash with your private key
    # at this point we sign the transaction using bitcoin core
    signed_raw_transaction = "01000000000101e336ce61815d8994e4975f94c53f1b80d836027d3c323a47e47f5da715dc29050100000000ffffffff01282300000000000022002012bd027208ce2c995ec6d15425934ce52a6087248da62ff0c3d811f994d080d5024730440220589f043c452631911e2fd368af348b043dc03cd3e60868818d12d2975d0dee720220606202a038787672bef538883c796537d422bb9d72fd4130fa76395a7602e2a00121024be5e28a803e2bdd51ef5f41271dcc1283d102aa22040e7dfd3d469033892352ffffffff"

    # after sending the signed raw transaction we have funds locked to our secret
    # when we send the transaction we get a new transaction_id and a new transaction_index

    version = 1
    tx_id_to_spent = '838344326dcd6bb239368ddbbcf9f534eb8c65af5e95b538fdca19cf704a7476'
    tx_index_to_spent = 0
    amount_to_spent = 8000
    locktime = 0xffffffff
    
    # create a raw transaction
    # step 1: create the transaction input
    witness = Script([bytes.fromhex(secret_hex), bytes.fromhex(original_script_hex)])
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent, witness_script=witness)

    # step 2: create the transaction output 
    transaction_output = TxOut(amount_to_spent, p2wsh)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    print(raw_transaction.serialize_segwit().hex())

if __name__ == "__main__":
    
    main()
