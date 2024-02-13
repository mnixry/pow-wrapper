import hashlib
import string
import itertools

import pwn
import re


def proof_of_work(nonce: str, difficulty: int):
    nonce_byte = nonce.encode()
    for salt in itertools.chain.from_iterable(
        map(
            bytes,
            itertools.product(
                (string.ascii_letters + string.digits).encode(), repeat=i
            ),
        )
        for i in itertools.count(1)
    ):
        if (
            hashlib.sha256(nonce_byte + salt).hexdigest()[:difficulty]
            == "0" * difficulty
        ):
            return salt
    raise ValueError("No solution found")


p = pwn.remote("localhost", 1337)

matched = re.search(
    r"sha256\('(?P<nonce>[-A-Za-z0-9+/]+?)'.*?\)(?:.*?)startswith\('0'\s*\*\s*(?P<diff>\d+)\)",
    p.recvuntil(b"== ").decode(),
)
assert matched, "No proof of work found"
nonce = matched.group("nonce")
difficulty = int(matched.group("diff"))
p.send(proof_of_work(nonce, difficulty))
p.interactive()
