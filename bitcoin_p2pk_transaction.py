from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes
from transaction import Tx, TxIn, TxOut
from script import Script, p2pk_script, p2pkh_script
from format_converter import Converter
from io import BytesIO


# the elliptical curve bitcoin is using
curve = ECDSA('secp256k1')
bitcoin = Bitcoin()
hash = Hashes()
converter = Converter()



def main():

    private_key_wif = 'cQSweeycwBXRDfaRAULP72fnaobvZVkcQoQVhJpUPsMULxjK8oJK'
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    version = 1
    tx_id_to_spent = 'e0daceeaefa40ac7f3ff5298b9c3023a269a20a7aef38426d351af0cc3609649'
    tx_index_to_spent = 0
    script_pub_key_to_spent = '76a9148f39b19cb47396288b17c3a9f019119a140ba40088ac'
    amount_to_spent = 9000
    #receiver_address = "mrYNwKBkzX8PdNPGmfPiXyertDXvJnDWPa"
    locktime = 0xffffffff

    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)
    
    # step 2: create the transaction output
    # aus der addresse herraus kann nur der hash des publickey abgeleitet werden
    # daher muss der eigentliche public key des receivers aus dem private key des receivers berechnet werden
    private_key_wif_receiver = 'cS1U7iREGpYmDuW7hRWGEyhirJudGptEwEDUmBKaPjeu9aRRSnxH'
    private_key_int_receiver = converter.convert_private_key_wif_to_int(private_key_wif_receiver)

    public_key_receiver = curve.calculate_public_key(private_key_int_receiver, compressed=True)
    script_pubkey = p2pk_script(public_key_receiver)
    
    transaction_output = TxOut(amount_to_spent, script_pubkey)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)
    
    # step 3: sign the sig hash with your private key
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    raw_transaction.sign_input(0, private_key_int, script_sig)

    print("This is your signed raw p2pk transaction")
    print(raw_transaction.serialize().hex())

    
    # now we want to spend the p2pk transaction
    version = 1
    tx_id_to_spent = 'f60044de9eadb365c03d47907c200705194b2d9bbdf307d398f234143de3f291'
    tx_index_to_spent = 0
    script_pub_key_to_spent = '210377708dd31f718fab3178084a7cf5a8e6bf1e7c4079af5bf9f8c5a0a69a3dd31eac'
    amount_to_spent = 8000
    receiver_address = "mqFPkGEwujzzz6bPTdco86t3bhpPgDSvSm"
    locktime = 0xffffffff

    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)

    # step 2: create the transaction output
    script_pubkey_receiver = p2pkh_script(converter.decode_base58(receiver_address))
    transaction_output = TxOut(amount_to_spent, script_pubkey_receiver)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)
    
    # step 3: sign the sig hash with your private key
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    raw_transaction.sign_input_p2pk(0, private_key_int_receiver, script_sig)

    print("This is your signed raw p2pkh transaction to spent the p2pk utxo")
    print(raw_transaction.serialize().hex()) 


if __name__ == "__main__":
    main()