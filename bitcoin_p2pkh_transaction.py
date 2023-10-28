from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes
from transaction import Tx, TxIn, TxOut
from script import Script, p2pkh_script
from format_converter import Converter
from io import BytesIO


# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()
converter = Converter()



def main():

    private_key_wif = "cTwMnFm86YFcQRqzNUfV1ygpKPU78NUqW8m4t3oqWmeEs1gcfDo1"
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    version = 1
    tx_id_to_spent = 'ca0bf9d6344c56bac32c0e707eb853d162ee6376b7a5d062754ba205281f69d5'
    tx_index_to_spent = 1
    script_pub_key_to_spent = '76a91488fd87526e486c18b2f232df6cb15109a45e9dac88ac'
    amount_to_spent = 9000
    receiver_address = "mhqPXXnKfzhNUk8DNjSkYhwe81u3PTPDut"
    locktime = 0xffffffff

    # create an unsigned raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)
    
    # step 2: create the transaction output -> will be a new p2pkh scriptPubKey
    script_pubkey_receiver = p2pkh_script(converter.decode_base58(receiver_address))
    transaction_output = TxOut(amount_to_spent, script_pubkey_receiver)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)
    
    # step 3: sign the sig hash with your private key
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    raw_transaction.sign_input(0, private_key_int, script_sig)

    print("This is your signed raw p2pkh transaction")
    print(raw_transaction.serialize().hex())

if __name__ == "__main__":
    main()

