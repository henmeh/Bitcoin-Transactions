from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes

# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()


def main():

    private_key_wif: str = "cUJqaouk7yMJjPWNp21BJ6bC6gPjFfjnKbXkkETCJvZ6TiHuwDcA"
    address_receiver: str = "mg6W3QKu6G5LRkXmKdayLN213sFuhESVgu"
    tx_to_spent_from_hex: str = "80cf84760f5f75369d2c81c65793ff8100988027e3d08dd37bdb252fa4e470c4"
    scriptPubKey_from_tx_to_spent_from_hex: str = "76a914cb0b589d96c4e88684e39a990712ecdbe3cd727188ac"
    vout: str = "1"
    amount_satoshi: int = 9000
    sighash_flag_hex = "01"

    
    script_pub_key_hex = bitcoin.calculate_p2pkh_scriptPubKey(address_receiver)
    _, unsigned_raw_transaction = bitcoin.create_raw_transaction(tx_to_spent_from_hex, vout, scriptPubKey_from_tx_to_spent_from_hex, amount_satoshi, script_pub_key_hex)
    print(unsigned_raw_transaction)

    script_sig_hex = bitcoin.calculate_p2pkh_scriptSig(unsigned_raw_transaction, private_key_wif, sighash_flag_hex)
    _, signed_raw_transaction = bitcoin.create_raw_transaction(tx_to_spent_from_hex, vout, script_sig_hex, amount_satoshi, script_pub_key_hex)
    
    print("-----------------------------------------------")
    print(signed_raw_transaction)


if __name__ == "__main__":
    main()

