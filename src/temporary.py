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

transaction = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
tx_parsed = CTx.parse_transaction(BytesIO(bytes.fromhex(transaction)))

script_pubkey = "a9149993a429037b5d912407a71c252019287b8d27a587"
amount = int(9.87654321 * 100000000)
redeemScript = "0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
witness_script = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"


print(hex(tx_parsed.get_sig_hash_for_segwit_transaction(0, amount, witness_script))[2:] == "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c")

tx_parsed.sign_transaction(0, [1234], previous_script_pubkey=Script.parse_script(BytesIO(bytes.fromhex(script_pubkey))), redeem_script=Script.parse_script(BytesIO(bytes.fromhex(redeemScript))), witness_script=Script.parse_script(BytesIO(bytes.fromhex(witness_script))), input_amount=amount)
