import sys

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.ecdsa import PrivateKey, PublicKey, Secp256k1, Signature

priv_key = PrivateKey(2 ** 256 - 2 ** 199)
wif = priv_key.convert_to_wif_format()

print(wif)
