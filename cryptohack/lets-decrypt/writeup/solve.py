# Let's Decrypt — the server signs ONE fixed message with its real key, but `verify`
# raises that fixed signature under OUR (n, e). Pick a regex-matching message, compute
# its padded digest T, then submit e = 1, n = S - T:
#
#     pow(S, 1, S - T) = S mod (S - T) = T        (S = n + T with T < n)
#
# Note: the deployed emsa_pkcs1_v15 pads with SHA-1 (not the SHA-256 the source imports).

import socket, json, hashlib

HOST, PORT = "socket.cryptohack.org", 13391
SHA1_DIGESTINFO = bytes.fromhex("3021300906052b0e03021a05000414")

def emsa_pkcs1_v15(msg, k=256):            # 00 01 || FF*218 || 00 || DigestInfo || hash
    t = SHA1_DIGESTINFO + hashlib.sha1(msg).digest()
    return int.from_bytes(b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t, "big")

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

msg = "I am Mallory and I own CryptoHack.org"

s.sendall(json.dumps({"option": "get_signature"}).encode() + b"\n")
S = int(readjson()["signature"], 16)
print(f"[*] signature S: {S.bit_length()} bits")

T = emsa_pkcs1_v15(msg.encode())
n, e = S - T, 1
assert pow(S, e, n) == T                    # sanity: the digest check will pass

s.sendall(json.dumps({"option": "verify", "msg": msg, "N": hex(n), "e": "0x1"}).encode() + b"\n")
print(readjson())
s.close()
