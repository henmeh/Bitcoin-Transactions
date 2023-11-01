from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes
from transaction import Tx, TxIn, TxOut
from helper_functions import Converter
from script import Script, p2wpkh_script
# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()
converter = Converter()


def main():
    private_key_wif = 'cR6XtmTbs4JWGiQhXscKV5wZs4xsDumDD6gHZisPjbF17B91JLRZ'
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    version = 1
    tx_id_to_spent = '9e4d423e73db7cacab4e45fbd8dd6e51a68e63e91a618d4a4f581f873cc906ed'
    tx_index_to_spent = 1
    tx_sequence_to_spent = 0xfeffffff
    script_pub_key_to_spent = ''
    amount_to_spent = 9000
    receiver_address = "bcrt1qrwlamh2txgu9lk8m5c7yvqwcmrffwzr7xkykds"
    locktime = 0xffffffff

    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)
    
    # step 2: create the transaction output
    script_pubkey = p2wpkh_script(bitcoin.bech32_address_to_script_pubkey("bcrt", receiver_address))
    transaction_output = TxOut(amount_to_spent, script_pubkey)
  
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime, is_segwit=True)
    print(raw_transaction.serialize().hex())
    
    # step 3: sign the sig hash with your private key
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    #script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    #raw_transaction.sign_input(0, private_key_int, script_sig)

    #print("This is your signed raw p2pk transaction")
    #print(raw_transaction.serialize().hex())


if __name__ == "__main__":
    main()