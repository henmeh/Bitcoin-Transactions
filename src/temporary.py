import sys
sys.path.append('/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/')

from src.ecdsa import PublicKey, Signature, Secp256k1, PrivateKey

priv_key = PrivateKey(888**3)
pub_key = priv_key.get_public_key()

address1 = pub_key.calculate_base58_address(compressed=True, testnet=False)
address2 = pub_key.calculate_base58_address(compressed=True, testnet=True)


print(address1)
print(address2)
