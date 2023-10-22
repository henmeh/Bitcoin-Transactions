from bitcoin_transaction_helpers import ECDSA, Bitcoin, Hashes

# the elliptical curve bitcoin is using
curve = ECDSA("secp256k1")
bitcoin = Bitcoin()
hash = Hashes()


def main():

    #doing some tests, will be deleted when a real transaction goes through
    from format_converter import Converter
    from script import p2pkh_script
    from transaction import TxIn, TxOut, Tx
    from io import BytesIO
    
    converter = Converter()
    
    prev_tx = bytes.fromhex('0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299')
    prev_index = 13
    tx_in = TxIn(prev_tx, prev_index)
    tx_outs = []
    change_amount = int(0.33*100000000)
    change_h160 = converter.decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
    change_script = p2pkh_script(change_h160)
    change_output = TxOut(amount=change_amount, script_pubkey=change_script)
    target_amount = int(0.1*100000000)
    target_h160 = converter.decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
    target_script = p2pkh_script(target_h160)
    target_output = TxOut(amount=target_amount, script_pubkey=target_script)
    tx_obj = Tx(1, [tx_in], [change_output, target_output], 0, True)
    print(tx_obj)

    raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    stream = BytesIO(raw_tx)
    tx = Tx.parse(stream)
    print(tx.version == 1)

    raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    stream = BytesIO(raw_tx)
    tx = Tx.parse(stream)
    print(tx.serialize() == raw_tx)

    raw_tx = bytes.fromhex('0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600')
    stream = BytesIO(raw_tx)
    tx = Tx.parse(stream)
    print(len(tx.tx_ins) == 1)
    want = bytes.fromhex('d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81')
    print(tx.tx_ins[0].prev_tx_id == want)
    print(tx.tx_ins[0].prev_index == 0)
    want = bytes.fromhex('6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a')
    print(tx.tx_ins[0].script_sig.serialize() == want)
    print(tx.tx_ins[0].sequence == 0xfffffffe)
    

if __name__ == "__main__":
    main()

