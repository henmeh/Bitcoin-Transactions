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

transaction = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(transaction)))

print(hex(tx_parsed.get_sig_hash_for_segwit_transaction(0, 10*100000000, "001479091972186c449eb1ded22b78e40d009bdf0089")))
