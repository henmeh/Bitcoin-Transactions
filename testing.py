from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes
from transaction import Tx, TxIn, TxOut
from script import Script, p2pkh_script, p2sh_script
from format_converter import Converter
from io import BytesIO
from unittest import TestCase



# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()
converter = Converter()


def test_for_p2pkh_transaction():
    private_key_wif = "cTwMnFm86YFcQRqzNUfV1ygpKPU78NUqW8m4t3oqWmeEs1gcfDo1"
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    version = 1
    tx_id_to_spent = 'ca0bf9d6344c56bac32c0e707eb853d162ee6376b7a5d062754ba205281f69d5'
    tx_index_to_spent = 1
    script_pub_key_to_spent = '76a91488fd87526e486c18b2f232df6cb15109a45e9dac88ac'
    amount_to_spent = 9000
    receiver_address = "mhqPXXnKfzhNUk8DNjSkYhwe81u3PTPDut"
    locktime = 0xffffffff

    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)
    script_pubkey_receiver = p2pkh_script(converter.decode_base58(receiver_address))
    transaction_output = TxOut(amount_to_spent, script_pubkey_receiver)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)
    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    raw_transaction.sign_input(0, private_key_int, script_sig)

    print(raw_transaction.serialize().hex() == "0100000001d5691f2805a24b7562d0a5b77663ee62d153b87e700e2cc3ba564c34d6f90bca010000006a473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02207d788ef22d22ba7373a3ab2f70cea2475c75fb8bc78a2c4d71fb9d05fd724d3a012103c4f5245042eab9fe9fcd5c575f0dbcb2713b796bf62194dab3c4515ed1f9eec8ffffffff0128230000000000001976a914196ccd42e9392eba4baeccc27046373e9c0e91e388acffffffff")


def test_for_p2sh_transaction():
    version = 1
    tx_id_to_spent = '99d237f85942a1fcdeee2c731cb40b1ba475a66bbff580bc7a20a4f11cf32c23'
    tx_index_to_spent = 0
    amount_to_spent = 8000
    locktime = 0xffffffff
    secret = "this is base58 yall"
    secret_hex = converter.convert_string_to_hex(secret)
    original_script = Script([bytes.fromhex(secret_hex), 0x87])
    original_script_hex = original_script.serialize().hex()[2:] #serialize will give back also the length of the total script, but this is not part of the hashing data  
    original_script_hash160 = hash.hash160(bytes.fromhex(original_script_hex))
    ps2h = p2sh_script(original_script_hash160)
    
    script_sig = Script([bytes.fromhex(secret_hex), bytes.fromhex(original_script_hex)])
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent, script_sig=script_sig)
    
    transaction_output = TxOut(amount_to_spent, ps2h)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    print(raw_transaction.serialize().hex() == "0100000001232cf31cf1a4207abc80f5bf6ba675a41b0bb41c732ceedefca14259f837d299000000002a1374686973206973206261736535382079616c6c151374686973206973206261736535382079616c6c87ffffffff01401f00000000000017a91463b256137edbbaaad52286528c4dd75a393427bc87ffffffff")


def test_for_p2pk_transaction():
    version = 1
    tx_id_to_spent = 'f60044de9eadb365c03d47907c200705194b2d9bbdf307d398f234143de3f291'
    tx_index_to_spent = 0
    script_pub_key_to_spent = '210377708dd31f718fab3178084a7cf5a8e6bf1e7c4079af5bf9f8c5a0a69a3dd31eac'
    amount_to_spent = 8000
    receiver_address = "mqFPkGEwujzzz6bPTdco86t3bhpPgDSvSm"
    locktime = 0xffffffff
    private_key_wif_receiver = 'cS1U7iREGpYmDuW7hRWGEyhirJudGptEwEDUmBKaPjeu9aRRSnxH'
    private_key_int_receiver = converter.convert_private_key_wif_to_int(private_key_wif_receiver)

    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent)

    script_pubkey_receiver = p2pkh_script(converter.decode_base58(receiver_address))
    transaction_output = TxOut(amount_to_spent, script_pubkey_receiver)
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime)

    script_sig = Script().parse(BytesIO(bytes.fromhex(f"{hex(len(script_pub_key_to_spent)//2)[2:]}{script_pub_key_to_spent}")))
    raw_transaction.sign_input_p2pk(0, private_key_int_receiver, script_sig)

    print(raw_transaction.serialize().hex() == "010000000191f2e33d1434f298d307f3bd9b2d4b190507207c90473dc065b3ad9ede4400f60000000048473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb0220025c8bd849c4bd110f0a022d4a668d578c5de2b6660b9598f94d62cef8ec66f301ffffffff01401f0000000000001976a9146abfd93ee84140a3c6db55bc5903561c995b392888acffffffff") 


def main():
    test_for_p2pkh_transaction()
    test_for_p2sh_transaction()
    test_for_p2pk_transaction()


if __name__ == "__main__":
    main()