from bitcoin_transaction_helpers import ECDSA, Hashes, Bitcoin

# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()


def main():

    private_key_wif: str = "cS4EmX16hg3otvekPZX4X9kYcPtT6QMiJpg8fRuWQo6kL52ykXXN"
    tx_to_spent_from_hex: str = "80c4adf5f956200bca1cdb019b7a84b58df1291354cfe15ff898c27a75739088"
    script_pubkey_from_tx_to_spent_from_hex: str = "76a914ab54a298577127ae7d64e2671d5f9fbea8675e8888ac"
    vout: str = "1"
    amount_to_spent_satoshi: int = 9000
    secret = "we make it visible"
    sighash_flag_hex = "01"

    _, p2sh_script, _ = bitcoin.calculate_p2sh_scriptPubKey(secret)
    unsigned_transaction_dict, unsigned_raw_transaction = bitcoin.create_raw_transaction(tx_to_spent_from_hex, vout, script_pubkey_from_tx_to_spent_from_hex, amount_to_spent_satoshi, p2sh_script)

    print(unsigned_raw_transaction)


    script_sig_hex = bitcoin.calculate_p2pkh_scriptSig(unsigned_raw_transaction, private_key_wif, sighash_flag_hex)
    signed_raw_transaction_dict, signed_raw_transaction = bitcoin.create_raw_transaction(tx_to_spent_from_hex, vout, script_sig_hex, amount_to_spent_satoshi, p2sh_script)
    print("---------------------------------------")
    print(signed_raw_transaction)


    # after sending the signed raw transaction we have funds locked to our secret
    # notice that we did not use an anddress to send funds!!!

    # calculating the scriptSig for spending the funds locked to our secret
    tx_for_locking_the_funds_to_secret = "45b770d1e72af01bcb58eba44c98a8b97097201df3f884f9c24cfda14d7ea0d2"
    vout: str = "0"
    amount_to_spent_satoshi: int = 8000

    script_sig_hex = bitcoin.calculate_p2sh_scriptSig(secret)

    # WATCH OUT!!! WE SPEND THE FUNDS TO THE SAME SECRET AGAIN. NEVER DO THIS IN REAL LIFE. OUR TX IS ONLY ON TESTNET SO YOLO!!!
    signed_raw_transaction_dict, signed_raw_transaction = bitcoin.create_raw_transaction(tx_for_locking_the_funds_to_secret, vout, script_sig_hex, amount_to_spent_satoshi, p2sh_script)
    print("---------------------------------------")
    print(signed_raw_transaction)

    # now we can send this raw transaction
    # note that we did not use the step sign tx because we already knew the scriptSig


if __name__ == "__main__":
    
    main()