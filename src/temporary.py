import sys
sys.path.insert(0, "/media/henning/Volume/Programming/Bitcoin/bitcoin/test/functional")
from test_framework.test_shell import TestShell
from io import BytesIO
from decimal import Decimal

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.ecdsa import PrivateKey
from src.transaction import CTx, CTxIn, CTxOut
from src.script import Script, p2wpkh_script, p2pkh_script, p2wsh_script, p2ms_script, p2pk_script
from src.crypto import hash160, hash256, sha256


test = TestShell().setup(num_nodes=3, setup_clean_chain=True)
alice = test.nodes[0]
bob = test.nodes[1]
charlie = test.nodes[2]

alice.createwallet("alice", descriptors=False)
bob.createwallet("bob", descriptors=False)
charlie.createwallet("charlie", descriptors=False)

alice_address_0 = alice.getnewaddress("", "legacy")
test.generatetoaddress(alice, 101, alice_address_0)

alice_address_1 = alice.getnewaddress("", "legacy")
alice_p2sh_funding_tx = alice.sendtoaddress(alice_address_1, 0.00011)
alice_p2sh_funding_tx_parsed = alice.decoderawtransaction(alice.gettransaction(alice_p2sh_funding_tx)["hex"])
test.generatetoaddress(alice, 1, alice_address_0)

bob_address_1 = bob.getnewaddress("", "legacy")
bob_private_key_wif_format = bob.dumpprivkey(bob_address_1)
bob_private_key = PrivateKey.convert_wif_format(bob_private_key_wif_format)
bob_private_key_int_format = bob_private_key.get_private_key_int()
bob_public_key = bob_private_key.get_public_key()

charlie_address_1 = charlie.getnewaddress("", "legacy")
charlie_private_key_wif_format = charlie.dumpprivkey(charlie_address_1)
charlie_private_key = PrivateKey.convert_wif_format(charlie_private_key_wif_format)
charlie_private_key_int_format = charlie_private_key.get_private_key_int()
charlie_public_key = charlie_private_key.get_public_key()


bob_and_charlie_skript = p2ms_script([bob_public_key.sec_format(), charlie_public_key.sec_format()], 2, 2)
bob_and_charlie_skript_hash160 = sha256(bytes.fromhex(bob_and_charlie_skript.serialize_script().hex()[2:]))


alice_private_key_wif_format = alice.dumpprivkey(alice_address_1)
alice_private_key = PrivateKey.convert_wif_format(alice_private_key_wif_format)
alice_private_key_int_format = alice_private_key.get_private_key_int()
alice_public_key = alice_private_key.get_public_key()

alice_previous_tx_id_to_spent = alice_p2sh_funding_tx_parsed["txid"]

for tx_out in alice_p2sh_funding_tx_parsed["vout"]:
    if tx_out["value"] == Decimal("0.00011000"):
        alice_previous_tx_index_to_spent = tx_out["n"]
        alice_previous_script_pub_key_to_spent = tx_out["scriptPubKey"]["hex"]

#Transaktionsoutputdaten
alice_amount_to_spent = 10000


transaction_input = CTxIn(bytes.fromhex(alice_previous_tx_id_to_spent), alice_previous_tx_index_to_spent, script_sig=Script())

alice_script_pubkey = p2wsh_script(bob_and_charlie_skript_hash160)
transaction_output = CTxOut(alice_amount_to_spent, alice_script_pubkey)

alice_locking_transaction = CTx(1, [transaction_input], [transaction_output], 0xffffffff, is_testnet=True, is_segwit=False)

#print(f"Alice unsignierte P2WSH Lockingtransaktion: {alice_locking_transaction.serialize_transaction().hex()}")


alice_script_sig = Script().parse_script(BytesIO(bytes.fromhex(f"{hex(len(alice_previous_script_pub_key_to_spent)//2)[2:]}{alice_previous_script_pub_key_to_spent}")))
alice_locking_transaction.sign_transaction(0, [alice_private_key_int_format], alice_script_sig)

#print(f"Alice signierte P2WSH Lockingtransaktion: {alice_locking_transaction.serialize_transaction().hex()}")

alice_p2sh_locking_tx = alice.sendrawtransaction(alice_locking_transaction.serialize_transaction().hex())
test.generatetoaddress(alice, 1, alice_address_0)


alice_p2ms_locking_tx_parsed = alice.decoderawtransaction(alice.gettransaction(alice_p2sh_locking_tx)["hex"])

bob_previous_tx_id_to_spent = alice_p2ms_locking_tx_parsed["txid"]

for tx_out in alice_p2ms_locking_tx_parsed["vout"]:
    if tx_out["value"] == Decimal("0.00010000"):
        bob_previous_tx_index_to_spent = tx_out["n"]
        bob_previous_script_pub_key_to_spent = tx_out["scriptPubKey"]["hex"]

#Transaktionsoutputdaten
bob_amount_to_spent = 9000
#bob's reciever address is alice public key


transaction_input = CTxIn(bytes.fromhex(bob_previous_tx_id_to_spent), bob_previous_tx_index_to_spent, script_sig=Script())

script_pubkey = p2pk_script(alice_public_key.sec_format())
transaction_output = CTxOut(bob_amount_to_spent, script_pubkey)

bob_spending_transaction = CTx(1, [transaction_input], [transaction_output], 0xffffffff, is_testnet=True, is_segwit=True)

#print(f"Bob unsignierte P2WSH Spendingtransaktion: {bob_spending_transaction.serialize_transaction().hex()}")




bob_script_sig = Script().parse_script(BytesIO(bytes.fromhex(f"{hex(len(bob_previous_script_pub_key_to_spent)//2)[2:]}{bob_previous_script_pub_key_to_spent}")))

bob_spending_transaction.sign_transaction(0, [bob_private_key_int_format, charlie_private_key_int_format], bob_script_sig, 2, 2, bob_and_charlie_skript, input_amount=alice_amount_to_spent)

print(f"Bob signierte P2WSH Spendingtransaktion: {bob_spending_transaction.serialize_transaction().hex()}")

bob_p2ms_spending_tx = bob.sendrawtransaction(bob_spending_transaction.serialize_transaction().hex())


TestShell().shutdown()