import sys

sys.path.append("/media/henning/Volume/Programming/Bitcoin/Bitcoin-Transactions/")

from src.script import p2pk_script


print(p2pk_script(b'123'))