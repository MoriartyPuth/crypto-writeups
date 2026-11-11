# Blinding Light — the server signs any message that doesn't contain the literal
# bytes "admin=True", but textbook RSA signing is multiplicatively malleable:
#
#     Sig' = (M * r^e)^d = M^d * r^(ed)  ->  Sig' * r^-1 = M^d * r^(ed-1) = M^d  (mod N)
#
# So blind the admin token with r^e, get it signed, unblind by r^-1, verify.

import socket, json
from math import gcd

HOST, PORT = "socket.cryptohack.org", 13376
ADMIN = b"admin=True"

s = socket.create_connection((HOST, PORT), timeout=30)

def readjson():
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk: raise EOFError
        buf += chunk
        try: return json.loads(buf)
        except json.JSONDecodeError:
            if buf.endswith(b"\n"): buf = b""   # drop the plain-text banner line

def query(obj):
    s.sendall(json.dumps(obj).encode() + b"\n")
    return readjson()

pub = query({"option": "get_pubkey"})
N, e = int(pub["N"], 16), int(pub["e"], 16)
print(f"[*] {N.bit_length()}-bit N, e={e}")

r = 2
while gcd(r, N) != 1:
    r += 1

blind = (int.from_bytes(ADMIN, "big") * pow(r, e, N)) % N
sig_prime = int(query({"option": "sign", "msg": blind.to_bytes((blind.bit_length() + 7) // 8, "big").hex()})["signature"], 16)

sig = sig_prime * pow(r, -1, N) % N          # unblind -> M^d mod N
assert pow(sig, e, N) == int.from_bytes(ADMIN, "big")

print(query({"option": "verify", "msg": ADMIN.hex(), "signature": hex(sig)}))
s.close()
