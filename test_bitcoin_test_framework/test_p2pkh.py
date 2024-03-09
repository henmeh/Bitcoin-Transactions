import sys
from io import BytesIO
sys.path.insert(0, "/media/henning/Volume/Programming/Bitcoin/bitcoin/test/functional")
sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")
from test_framework.test_framework import BitcoinTestFramework
from src.ecdsa import PrivateKey
from src.transaction import CTx, CTxIn, CTxOut
from src.script import Script, p2pkh_script
from src.crypto import hash160

class P2PKHTest(BitcoinTestFramework):
    
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.wallet_names = ["Alice", "Bob"]
        self.options.descriptors = False


    def create_wallet_data(self, node) -> dict:
        wallet_data = node.get_deterministic_priv_key()
        wallet_key_wif = wallet_data.key
        wallet_key_object = PrivateKey.convert_wif_format(wallet_key_wif)
        wallet_key_int = wallet_key_object.get_private_key_int() 
        wallet_address = wallet_data.address
        wallet_public_key = wallet_key_object.get_public_key()

        return {
            "wallet_private_key_wif": wallet_key_wif,
            "wallet_private_key_object": wallet_key_object,
            "wallet_private_key_int": wallet_key_int,
            "wallet_address": wallet_address,
            "wallet_public_key": wallet_public_key
        }
        

    def run_test(self):
        alice = self.nodes[0]
        bob = self.nodes[1]

        self.init_wallet(node=0)
        self.init_wallet(node=1)

        #Mining 101 Blocks to fund alice empyt wallet
        alice_wallet_0 = self.create_wallet_data(alice)
        alice_wallet_1 = self.create_wallet_data(alice)
        bob_wallet_1 = self.create_wallet_data(bob)

        self.generatetoaddress(alice, 101, alice_wallet_0["wallet_address"])
        
        alice_funding_amount = 11000     
        alice_p2pkh_funding_tx = alice.sendtoaddress(alice_wallet_1["wallet_address"], alice_funding_amount / 100000000)
        alice_p2pkh_funding_tx_serialized = alice.gettransaction(alice_p2pkh_funding_tx)["hex"]
        alice_p2pkh_funding_tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(alice_p2pkh_funding_tx_serialized)))

        self.generatetoaddress(alice, 1, alice_wallet_0["wallet_address"])
        
        alice_previous_tx_id_to_spent = alice_p2pkh_funding_tx
        for index, tx_out in enumerate(alice_p2pkh_funding_tx_parsed.tx_outs):
            if tx_out.amount == alice_funding_amount:
                alice_previous_tx_index_to_spent = index
                alice_previous_script_pub_key_to_spent = tx_out.script_pubkey.serialize_script().hex()

        #Transaktionsoutputdaten
        alice_amount_to_spent = 10000
        
        transaction_input = CTxIn(bytes.fromhex(alice_previous_tx_id_to_spent), alice_previous_tx_index_to_spent, script_sig=Script())
        alice_script_pubkey = p2pkh_script(hash160(bob_wallet_1["wallet_public_key"].sec_format()))
        transaction_output = CTxOut(alice_amount_to_spent, alice_script_pubkey)
        alice_locking_transaction = CTx(1, [transaction_input], [transaction_output], 0xffffffff, is_testnet=True, is_segwit=False)
        alice_script_sig = Script().parse_script(BytesIO(bytes.fromhex(alice_previous_script_pub_key_to_spent)))
        
        alice_locking_transaction.sign_transaction(0, [alice_wallet_1["wallet_private_key_int"]], alice_script_sig)

        alice_p2pkh_locking_tx = alice.sendrawtransaction(alice_locking_transaction.serialize_transaction().hex())
        
        self.generatetoaddress(alice, 1, alice_wallet_0["wallet_address"])

        bob_previous_tx_id_to_spent = alice_p2pkh_locking_tx
        alice_p2pkh_locking_tx_serialized = bob.gettransaction(alice_p2pkh_locking_tx)["hex"]
        alice_p2pkh_locking_tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(alice_p2pkh_locking_tx_serialized)))

        for index, tx_out in enumerate(alice_p2pkh_locking_tx_parsed.tx_outs):
            if tx_out.amount == alice_amount_to_spent:
                bob_previous_tx_index_to_spent = index
                bob_previous_script_pub_key_to_spent = tx_out.script_pubkey.serialize_script().hex()

        #Transaktionsoutputdaten
        bob_amount_to_spent = 9000
        #bob's reciever address is alice public key

        transaction_input = CTxIn(bytes.fromhex(bob_previous_tx_id_to_spent), bob_previous_tx_index_to_spent, script_sig=Script())
        script_pubkey = p2pkh_script(hash160(alice_wallet_0["wallet_public_key"].sec_format()))
        transaction_output = CTxOut(bob_amount_to_spent, script_pubkey)
        bob_spending_transaction = CTx(1, [transaction_input], [transaction_output], 0xffffffff, is_testnet=True, is_segwit=False)
        bob_script_sig = Script().parse_script(BytesIO(bytes.fromhex(bob_previous_script_pub_key_to_spent)))
        bob_spending_transaction.sign_transaction(0, [bob_wallet_1["wallet_private_key_int"]], bob_script_sig)

        bob_p2pkh_spending_tx = bob.sendrawtransaction(bob_spending_transaction.serialize_transaction().hex())

if __name__ == '__main__':
    P2PKHTest().main()