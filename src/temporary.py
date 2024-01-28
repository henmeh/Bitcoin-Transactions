import sys
sys.path.append('/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/')

from src.ecdsa import PublicKey, Signature, Secp256k1


signature = Signature(0x08f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb, 0x7577710fa3ff7f89576c74909b932f778c2b34ec1571973bc8c24987df006255)
der = signature.der()

print(der)
print(bytes.fromhex("3044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02207577710fa3ff7f89576c74909b932f778c2b34ec1571973bc8c24987df006255"))