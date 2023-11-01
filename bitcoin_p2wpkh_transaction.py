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
    script_pub_key_to_spent = ''
    amount_to_spent = 9000
    receiver_address = "bcrt1qrwlamh2txgu9lk8m5c7yvqwcmrffwzr7xkykds"
    locktime = 0xffffffff

    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)
    
    # step 2: create the transaction output
    script_pubkey = p2wpkh_script(bitcoin.bech32_address_to_script_pubkey("bcrt", receiver_address))
    #print(script_pubkey.serialize(is_segwit=True).hex())
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

#bcr
#02000000000101 499660c30caf51d32684f3aea7209a263a02c3b99852fff3c70aa4efeacedae0 01 00000000 feffffff 02 edab042a01000000 16 001475766e85878716dd4fa5cf3319bd426fa6908e82 0247304402201bfbc8801be5a4cf23c6a68b8ed458a8e5d55ab2a2469064e72ae6b6b410bada02201522331d19c6748c5723cf4fa995fcb2d0e063c86e6eafa5cb8c2768aa4932610121024fdd0bfde4d617fed3c892a980a8673baa913968acf0f2d6bf119ee31d6ce10200000000

#python
#01000000000101 ed06c93c871f584f4a8d611ae9638ea6516eddd8fb454eabac7cdb733e424d9e 01 00000000 ffffffff 01 2823000000000000 16 00141bbfdddd4b32385fd8fba63c4601d8d8d297087e 0247304402201bfbc8801be5a4cf23c6a68b8ed458a8e5d55ab2a2469064e72ae6b6b410bada02201522331d19c6748c5723cf4fa995fcb2d0e063c86e6eafa5cb8c2768aa4932610121024fdd0bfde4d617fed3c892a980a8673baa913968acf0f2d6bf119ee31d6ce102ffffffff


#01000000000101ed06c93c871f584f4a8d611ae9638ea6516eddd8fb454eabac7cdb733e424d9e0100000000ffffffff0128230000000000001600141bbfdddd4b32385fd8fba63c4601d8d8d297087e0247304402201bfbc8801be5a4cf23c6a68b8ed458a8e5d55ab2a2469064e72ae6b6b410bada02201522331d19c6748c5723cf4fa995fcb2d0e063c86e6eafa5cb8c2768aa4932610121024fdd0bfde4d617fed3c892a980a8673baa913968acf0f2d6bf119ee31d6ce102ffffffff