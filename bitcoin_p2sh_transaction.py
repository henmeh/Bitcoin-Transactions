from bitcoin_transaction_helpers import ECDSA, Hashes
from format_converter import Converter
from script import Script, p2sh_script
from transaction import TxIn, TxOut, Tx
from io import BytesIO

curve = ECDSA("secp256k1")
hash = Hashes()
converter = Converter()

def main():

    private_key_wif = "cNui4R368FDxHB75eZv59omoHXNtTH491XANtqvMCncNMbe4W8rs"
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    version = 1
    tx_id_to_spent = '471a6dad40934c01dbdcb1a5af7336a962a0f532800f5966e4991573f3db4910'
    tx_index_to_spent = 1
    script_pub_key_to_spent = '76a91421fc4fc37cbdffce0d9aadad2da14aadbbcb860788ac'
    amount_to_spent = 9000
    locktime = 0xffffffff

    # now we build the script we want to sent the funds   
    secret = "we make it visible"
    secret_hex = converter.convert_string_to_hex(secret)
    #original_script = Script([bytes.fromhex(secret_hex), 0x87])
    #original_script_2 = original_script.serialize().hex()
    #print(original_script_serialized)

    original_script_2 = f"{hex(len(secret_hex) // 2)}{secret_hex + '87'}"[2:]
    original_script_hash160 = hash.hash160(original_script_2.encode())

    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)

    # step 2: create the transaction output 
    ps2h = p2sh_script(original_script_hash160)
    transaction_output = TxOut(amount_to_spent, ps2h)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    # step 3: sign the sig hash with your private key
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    raw_transaction.sign_input(0, private_key_int, script_sig)

    print("This is your signed raw p2sh transaction")
    print(raw_transaction.serialize().hex())
    
    # after sending the signed raw transaction we have funds locked to our secret
    # calculating the scriptSig for spending the funds locked to our secret
    version = 1
    tx_id_to_spent = '23a22f69bddf1ca01ee4745b3cedbcb71fa50580b361c3b379b6c749d27ea88f'
    tx_index_to_spent = 0
    amount_to_spent = 8000
    locktime = 0xffffffff
    script_sig = original_script_2.encode()

    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent, script_sig=Script([bytes.fromhex(secret_hex), 0x87]))

    # step 2: create the transaction output 
    transaction_output = TxOut(amount_to_spent, ps2h)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    # step 3: sign the sig hash with your private key
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    #script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    #raw_transaction.sign_input(0, private_key_int, script_sig)

    print("This is your signed raw p2sh transaction")
    print(raw_transaction.serialize().hex())
    




if __name__ == "__main__":
    
    main()