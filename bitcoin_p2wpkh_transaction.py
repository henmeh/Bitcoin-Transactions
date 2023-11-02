from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes
from transaction import Tx, TxIn, TxOut
from helper_functions import Converter
from script import Script, p2wpkh_script, witness_script
# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()
converter = Converter()


def main():
    private_key_wif = 'cR8yhMPUP9PUs69GoCz9xLCRZoNtzPkFopGZkPQnAXhg3qhQhSo7'
    private_key_int = converter.convert_private_key_wif_to_int(private_key_wif)
    public_key = curve.calculate_public_key(private_key_int)
    version = 1
    tx_id_to_spent = '4e4a8b1abf7a4e67d34282bf666402d3660a7904aba79d1506300e54d9865428'
    tx_index_to_spent = 1
    tx_sequence_to_spent = 0xfffffffe
    script_pub_key_to_spent = '00140666dc30e4c7edadf3eeab348ef1899ad5d48ccb'
    amount_to_spent = 9000
    receiver_address = 'bcrt1qqqagxht279w2z3ztvgyd9vce7krud57m5f7ppl'
    locktime = 000000

    # at first we create a legacy transaction with empty script sig
    # create a raw transaction
    # step 1: create the transaction input
    transaction_input = TxIn(bytes.fromhex(tx_id_to_spent), tx_index_to_spent, sequence=tx_sequence_to_spent)
    
    # step 2: create the transaction output
    script_pubkey = p2wpkh_script(bitcoin.bech32_address_to_script_pubkey("bcrt", receiver_address))
    transaction_output = TxOut(amount_to_spent, script_pubkey)
  
    raw_transaction = Tx(version, [transaction_input], [transaction_output], locktime, is_segwit=True)
    #print(raw_transaction.serialize_legacy().hex())

    # calculating the script_code as hash vom public key des p2wpkh inputs
    script_code = witness_script(hash.hash160(public_key))

    raw_transaction.sign_input_segwit(0, private_key_int, script_code, amount_to_spent)

    print(raw_transaction.serialize_segwit().hex())


if __name__ == "__main__":
    main()


    #02000000
    #00
    #01
    #01
    #75fce46b98fa2b4bf2babdd52b4f0f67b991b3aa754ff423ac2ddea0efdfa253
    #00000000
    #00
    #feffffff
    #02
    #2bbd052a01000000
    #160014aa8ae39f2bfbd2f2d96667e0e79610d53606574a
    #1027000000000000
    #1600140666dc30e4c7edadf3eeab348ef1899ad5d48ccb
    #024730440220154ae7d85f923845e4fc037bc4590f5298742eba3be682532a680d45e278d0cd02204c58b402ef112c9da2a0c7ac571ac748e557d802a945798a4819f2bd18720a1f012103d66fb24670c310d5fa63589bdf5c4e8b84d202129d5a5120c71a482b1ceba691d6
    #000000


    #von bcr signierte raw_legacy transaction
    #01000000
    #00
    #01
    #01
    #285486d9540e3006159da7ab04790a66d3026466bf8242d3674e7abf1a8b4a4e
    #01000000
    #00
    #feffffff
    #01
    #2823000000000000
    #160014003a835d6af15ca1444b6208d2b319f587c6d3db
    #0247304402205836dad443f7eb5b5da74a95398922576efba6032af5ef542823b31473ef8a12022039ecd1ec293b2746205066723cb0365a81791165f6a8aee1ca82fe68fe1a90e601 21028793b987f18ddab17c8a1a9fb4d8e67eae186f3e75c4537f7e452b66a96bfab2
    #02473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb0220772062bcb02c0e9288bb775d73ce44f9685ab33cc7d281d5bd1c6c367afce3b601 21028793b987f18ddab17c8a1a9fb4d8e67eae186f3e75c4537f7e452b66a96bfab2
    #00000000


    #von python erstellte transaction
    #01000000
    #00
    #01
    #01
    #285486d9540e3006159da7ab04790a66d3026466bf8242d3674e7abf1a8b4a4e
    #01000000
    #00
    #feffffff
    #01
    #2823000000000000
    #160014003a835d6af15ca1444b6208d2b319f587c6d3db
    #02473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb0220772062bcb02c0e9288bb775d73ce44f9685ab33cc7d281d5bd1c6c367afce3b60121028793b987f18ddab17c8a1a9fb4d8e67eae186f3e75c4537f7e452b66a96bfab2
    #00000000