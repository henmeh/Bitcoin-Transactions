import sys
from io import BytesIO

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.ecdsa import PrivateKey
from src.transaction import CTx, CTxIn, CTxOut
from src.script import Script, p2wpkh_script
from src.crypto import hash160

test_transaction = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(test_transaction)))

#script_pubkey = p2wpkh_script(hash160(bytes.fromhex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")))
#print(script_pubkey.serialize_script())

script_pubkey = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
print(hex(tx_parsed.get_sig_hash_for_segwit_transaction(1, 600000000, script_pubkey=script_pubkey)))

test = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"
print(test[4:])
