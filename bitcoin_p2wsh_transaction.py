from bitcoin_transaction_helpers import ECDSA, Hashes, Bitcoin

# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()


def main():

    private_key_wif: str = "cQXSbyfRYebxHLFCJfGYifZmTryYhpSBA8Mtaz9gYfsuqGyX3XPS"
    tx_to_spent_from_hex: str = "de9101b9f6fd470a2f0a5ea9180d6f0ad771100e6e62254d3bac9e2bee1f5d96"
    script_pubkey_from_tx_to_spent_from_hex: str = "76a9146285653615b6d2bd47f2f7cd61cb47332ea6d28988ac"
    vout: str = "1"
    amount_to_spent_satoshi: int = 9000
    secret = "we make it visible"
    sighash_flag_hex = "01"

    #Step1: We have funds in a legacy address that we will send to a segwit scriptPubKey
    _, p2wsh_script, _ = bitcoin.calculate_p2wsh_scriptPubKey(secret)
    
    unsigned_raw_transaction_dict, unsigned_raw_transaction = bitcoin.create_raw_transaction(tx_to_spent_from_hex, vout, script_pubkey_from_tx_to_spent_from_hex, amount_to_spent_satoshi, p2wsh_script, is_segWit=False)

    print(unsigned_raw_transaction_dict)
    print(unsigned_raw_transaction)


    script_sig_hex = bitcoin.calculate_p2pkh_scriptSig(unsigned_raw_transaction, private_key_wif, sighash_flag_hex)
    
    signed_raw_transaction_dict, signed_raw_transaction = bitcoin.create_raw_transaction(tx_to_spent_from_hex, vout, script_sig_hex, amount_to_spent_satoshi, p2wsh_script, is_segWit=False)
    print("---------------------------------------")
    print(signed_raw_transaction_dict)
    print(signed_raw_transaction)


    # after sending the signed raw transaction we have funds locked to our secret in a segWit-Address

    # calculating the scriptSig for spending the funds locked to our secret
    tx_for_locking_the_funds_to_secret = "1166c176e42ca71b7f203f30bbb92dd61d8922e4b59357474e65ff06f1ee9903"
    vout: str = "0"
    amount_to_spent_satoshi: int = 8000

    # to quasi sign the data we must calculate our witness data
    witness = bitcoin.calculate_p2wsh_witness_data(secret)

    # WATCH OUT!!! WE SPEND THE FUNDS TO THE SAME SECRET AGAIN. NEVER DO THIS IN REAL LIFE. OUR TX IS ONLY ON TESTNET SO YOLO!!!
    signed_raw_transaction_dict, signed_raw_transaction = bitcoin.create_raw_transaction(tx_for_locking_the_funds_to_secret, vout, witness, amount_to_spent_satoshi, p2wsh_script, is_segWit=True)
    print("---------------------------------------")
    print(signed_raw_transaction)

    # now we can send this raw transaction
    # note that we did not use the step sign tx because we already knew the scriptSig


if __name__ == "__main__":
    
    main()
