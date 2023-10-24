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

    #print(private_key_int)

    version = 1
    tx_id_to_spent = 'ca0bf9d6344c56bac32c0e707eb853d162ee6376b7a5d062754ba205281f69d5'
    tx_index_to_spent = 1
    script_pub_key_to_spent = '76a91488fd87526e486c18b2f232df6cb15109a45e9dac88ac'
    amount_to_spent = 9000
    receiver_address = "mhqPXXnKfzhNUk8DNjSkYhwe81u3PTPDut"
    locktime = 0xffffffff

    # create an unsigned raw transaction
    # step 1: create the transaction input
    # the scriptSig must be the scriptPubKey from the transaction to spent from
    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent, script_sig=script_sig)
    #print(transaction_input.serialize().hex())
    # step 2: create the transaction output -> will be a new p2pkh scriptPubKey
    script_pubkey_receiver = p2pkh_script(converter.decode_base58(receiver_address))
    #print(script_pubkey_receiver.serialize().hex())
    transaction_output = TxOut(amount_to_spent, script_pubkey_receiver)
    #print(transaction_output.serialize().hex())
    unsigned_raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)
    #print(unsigned_raw_transaction.serialize().hex())

    # step 2: calculate the sig_hash_legacy for this legacy transaction
    sig_hash_legacy = unsigned_raw_transaction.sig_hash_legacy(1)
    #print(sig_hash_legacy)

    # step 3: sign the sig hash with your private key
    #signature = unsigned_raw_transaction.sign_input(1, PRIVATE_KEY)

    z = 12
    r, s = curve.sign_data(z, 123456789)
    print(hex(r))
    print(hex(s))
    
    print(curve.der(r, s).hex())

    from ecc import PrivateKey
    privKey = PrivateKey(123456789)
    sig = privKey.sign(z).der().hex()
    print(sig)
    



if __name__ == "__main__":
    main()

