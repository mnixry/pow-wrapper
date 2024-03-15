import hashlib
import string
import itertools

from pwn import remote
import sys
import re


program, *args = sys.argv
if len(args) != 2:
    print(f"Usage: {program} <target> <port>")
    sys.exit(1)
target, port = args

p = remote(target, port)


def proof_of_work(
    nonce: str,
    difficulty: int,
    salt_charset: str = string.ascii_letters + string.digits,
):
    nonce_byte = nonce.encode()
    for salt in itertools.chain.from_iterable(
        map(
            bytes,
            itertools.product(salt_charset.encode(), repeat=i),
        )
        for i in itertools.count(1)
    ):
        if (
            int.from_bytes(hashlib.sha256(nonce_byte + salt).digest(), "big")
            >> (256 - difficulty)
            == 0
        ):
            return salt
    raise ValueError("No solution found")

matched = re.search(
    r"nonce=(?P<nonce>.+?),\s*difficulty=(?P<diff>\d+)",
    p.recvuntil(b"salt:").decode(),
)

assert matched, "No proof of work found"
nonce = matched.group("nonce")
difficulty = int(matched.group("diff"))

p.send(proof_of_work(nonce, difficulty))
p.interactive()
