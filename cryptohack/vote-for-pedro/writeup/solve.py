# Vote for Pedro — Alice's vote "signature" is the vote itself: e = 3, no padding.
# The server accepts any v with pow(v, 3, N) ending (after the last \x00 byte) in
# "VOTE FOR PEDRO". Choose v ~ 2^120 so v^3 ~ 2^360 << N: no modular wraparound,
# and the check reduces to v^3 ≡ V (mod 256^15) with V = int("VOTE FOR PEDRO") —
# the \x00 above it is free since V < 256^14. V is odd and gcd(3, 2^k) = 1, so a
# unique odd cube root exists mod 2^120: recover it by Hensel lifting bit by bit
# (bit j of the correction = bit j of x^3 - V, since 3x^2 is odd).

import socket, json

HOST, PORT = "socket.cryptohack.org", 13375
MSG = b"VOTE FOR PEDRO"

def cube_root_mod_2k(V, k):
    """unique odd x with x^3 ≡ V (mod 2^k)"""
    x = 1
    for j in range(1, k):
        if ((x ** 3 - V) >> j) & 1:
            x += 1 << j
    assert (x ** 3 - V) % (1 << k) == 0
    return x

v = cube_root_mod_2k(int.from_bytes(MSG, "big"), 120)     # lift to mod 256^15
print(f"[*] forged vote: {v.bit_length()} bits, v^3: {(v ** 3).bit_length()} bits")

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

sig = v ** 3                                 # < N, so this is exactly pow(v, 3, N)
assert sig.to_bytes((sig.bit_length() + 7) // 8, "big").split(b"\x00")[-1] == MSG
print("[*] local check: verified vote ends with", b"\x00" + MSG)

s.sendall(json.dumps({"option": "vote", "vote": hex(v)}).encode() + b"\n")
print(readjson())
s.close()
