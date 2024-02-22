import sys

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.ecdsa import PrivateKey

test = PrivateKey.convert_wif_format("cVgAfaNWLeHR4fGgERYwVmYUwZ51D3d3BzFkxszxYdDG9vw99hLn")

print(test.get_private_key_int())