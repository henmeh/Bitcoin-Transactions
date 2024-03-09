import sys
sys.path.insert(0, "/media/henning/Volume/Programming/Bitcoin/bitcoin/test/functional")
from test_framework.test_shell import TestShell
from io import BytesIO
from decimal import Decimal

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.ecdsa import PrivateKey
from src.transaction import CTx, CTxIn, CTxOut
from src.script import Script, p2wpkh_script, p2pkh_script
from src.crypto import hash160

#test_transaction = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
#tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction)))

#script_pubkey = p2wpkh_script(hash160(bytes.fromhex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")))
#print(script_pubkey.serialize_script())

#script_pubkey = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
#print(hex(tx_parsed.get_sig_hash_for_segwit_transaction(1, 600000000, script_pubkey=script_pubkey)))

#test = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
#print(test[4:])



test = TestShell().setup(num_nodes=2, setup_clean_chain=True)
alice = test.nodes[0]
bob = test.nodes[1]

alice.createwallet("alice", descriptors=False)
bob.createwallet("bob", descriptors=False)

alice_address_0 = alice.getnewaddress("", "legacy")
test.generatetoaddress(alice, 101, alice_address_0)

alice_address_1 = alice.getnewaddress("", "legacy")
alice_p2wpkh_funding_tx = alice.sendtoaddress(alice_address_1, 0.00011)
alice_p2wpkh_funding_tx_parsed = alice.decoderawtransaction(alice.gettransaction(alice_p2wpkh_funding_tx)["hex"])
test.generatetoaddress(alice, 1, alice_address_0)

bob_address_1 = test.nodes[1].getnewaddress("")
bob_private_key_wif_format = bob.dumpprivkey(bob_address_1)
bob_private_key = PrivateKey.convert_wif_format(bob_private_key_wif_format)
bob_private_key_int_format = bob_private_key.get_private_key_int()
bob_public_key = bob_private_key.get_public_key()


alice_private_key_wif_format = alice.dumpprivkey(alice_address_1)
alice_private_key = PrivateKey.convert_wif_format(alice_private_key_wif_format)
alice_private_key_int_format = alice_private_key.get_private_key_int()
alice_public_key = alice_private_key.get_public_key()

alice_previous_tx_id_to_spent = alice_p2wpkh_funding_tx_parsed["txid"]

for tx_out in alice_p2wpkh_funding_tx_parsed["vout"]:
    if tx_out["value"] == Decimal("0.00011000"):
        alice_previous_tx_index_to_spent = tx_out["n"]
        alice_previous_script_pub_key_to_spent = tx_out["scriptPubKey"]["hex"]

#Transaktionsoutputdaten
alice_amount_to_spent = 10000


transaction_input = CTxIn(bytes.fromhex(alice_previous_tx_id_to_spent), alice_previous_tx_index_to_spent, script_sig=Script())

alice_script_pubkey = p2wpkh_script(hash160(bob_public_key.sec_format()))
transaction_output = CTxOut(alice_amount_to_spent, alice_script_pubkey)

alice_locking_transaction = CTx(1, [transaction_input], [transaction_output], 0xffffffff, is_testnet=True, is_segwit=False)

#print(f"Alice unsignierte P2WPK Lockingtransaktion: {alice_locking_transaction.serialize_transaction().hex()}")


alice_script_sig = Script().parse_script(BytesIO(bytes.fromhex(f"{hex(len(alice_previous_script_pub_key_to_spent)//2)[2:]}{alice_previous_script_pub_key_to_spent}")))
alice_locking_transaction.sign_transaction(0, [alice_private_key_int_format], alice_script_sig)

#print(f"Alice signierte P2WPKH Lockingtransaktion: {alice_locking_transaction.serialize_transaction().hex()}")

alice_p2wpkh_locking_tx = alice.sendrawtransaction(alice_locking_transaction.serialize_transaction().hex())
test.generatetoaddress(alice, 1, alice_address_0)

#print(alice_p2wpkh_locking_tx)


alice_p2wpk_locking_tx_parsed = alice.decoderawtransaction(alice.gettransaction(alice_p2wpkh_locking_tx)["hex"])

bob_previous_tx_id_to_spent = alice_p2wpk_locking_tx_parsed["txid"]

for tx_out in alice_p2wpk_locking_tx_parsed["vout"]:
    if tx_out["value"] == Decimal("0.00010000"):
        bob_previous_tx_index_to_spent = tx_out["n"]
        bob_previous_script_pub_key_to_spent = tx_out["scriptPubKey"]["hex"]

#Transaktionsoutputdaten
bob_amount_to_spent = 9000
#bob's reciever address is alice public key


transaction_input = CTxIn(bytes.fromhex(bob_previous_tx_id_to_spent), bob_previous_tx_index_to_spent, script_sig=Script())

script_pubkey = p2pkh_script(hash160(alice_public_key.sec_format()))
transaction_output = CTxOut(bob_amount_to_spent, script_pubkey)

bob_spending_transaction = CTx(1, [transaction_input], [transaction_output], 0xffffffff, is_testnet=True, is_segwit=True)

print(f"Bob unsignierte P2WPKH Spendingtransaktion: {bob_spending_transaction.serialize_transaction().hex()}")


bob_script_sig = Script().parse_script(BytesIO(bytes.fromhex(f"{hex(len(bob_previous_script_pub_key_to_spent)//2)[2:]}{bob_previous_script_pub_key_to_spent}")))
#print(bob_script_sig.serialize_script().hex())
bob_spending_transaction.sign_transaction(0, [bob_private_key_int_format], bob_script_sig, input_amount=10000)

print(f"Bob signierte P2PKH Spendingtransaktion: {bob_spending_transaction.serialize_transaction().hex()}")

bob_p2pkh_spending_tx = bob.sendrawtransaction(bob_spending_transaction.serialize_transaction().hex())

print(bob_p2pkh_spending_tx)


TestShell().shutdown()

