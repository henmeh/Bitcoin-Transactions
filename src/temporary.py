import sys

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.ecdsa import PrivateKey

test = PrivateKey.convert_wif_format("cSoDYWXxTwTbnWBpTsgWiaJbD4ZTLpJ51nHppZRFKtCK418ERJEo")

print(test.get_private_key_int())