from bitcoin_transaction_helpers import ECDSA, Hashes
from format_converter import Converter
from script import Script, p2sh_script
from transaction import TxIn, TxOut, Tx
from io import BytesIO

curve = ECDSA('secp256k1')
hash = Hashes()
converter = Converter()

def main():

    private_key_wif = 'cV6EkdS8sGkZ8Y68ZnpRDhaG33992y8jn5mwhvKs1x1DyjkjNRYr'
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    version = 1
    tx_id_to_spent = 'bef5dc9b6a59dae3d2998af4c6d934b24fe6e45ac318b7523cdcdcd233728973'
    tx_index_to_spent = 1
    script_pub_key_to_spent = '76a914ad49ea957570d4c831ed6ea47a7092eb8a736aa488ac'
    amount_to_spent = 9000
    locktime = 0xffffffff

    # now we build the script we want to sent the funds   
    secret = "this is base58 yall"
    secret_hex = converter.convert_string_to_hex(secret)
    original_script = Script([bytes.fromhex(secret_hex), 0x87])
    original_script_hex = original_script.serialize().hex()[2:] #serialize will give back also the length of the total script, but this is not part of the hashing data  
    original_script_hash160 = hash.hash160(bytes.fromhex(original_script_hex))
    
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

    print("This is your signed raw p2sh transaction to lock funds to a p2sh")
    print(raw_transaction.serialize().hex())
    
    # after sending the signed raw transaction we have funds locked to our secret
    version = 1
    tx_id_to_spent = '99d237f85942a1fcdeee2c731cb40b1ba475a66bbff580bc7a20a4f11cf32c23'
    tx_index_to_spent = 0
    amount_to_spent = 8000
    locktime = 0xffffffff
    
    # create a raw transaction
    # step 1: create the transaction input
    script_sig = Script([bytes.fromhex(secret_hex), bytes.fromhex(original_script_hex)])
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent, script_sig=script_sig)

    # step 2: create the transaction output 
    transaction_output = TxOut(amount_to_spent, ps2h)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    print("This is your signed raw p2sh transaction to spend a p2sh utxo")
    print(raw_transaction.serialize().hex())


if __name__ == "__main__":
    
    main()