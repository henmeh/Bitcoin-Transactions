import sys
sys.path.append('/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/')

from src.ecdsa import PublicKey, Signature, Secp256k1


pub_key = PublicKey(0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c, 0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
print(hex(pub_key.x_coordinate.num))
print(hex(pub_key.y_coordinate.num))

signature = Signature(0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395, 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4)
data = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60


print(Secp256k1().verify_signature(pub_key, signature, data))