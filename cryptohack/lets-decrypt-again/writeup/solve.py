#!/usr/bin/env python3
# Let's Decrypt Again (13394) — solver.
#
# The server signs one fixed statement with its real 768-bit key, lets us pick the
# modulus n ONCE per connection (must not be prime), but the exponent e PER CLAIM.
# Three regex/btc patterns yield three XOR-shares of the flag, so one n must serve
# three different padded digests T_i:   pow(S, e_i, n) == T_i.
#
# Construction: n = p * 256, p prime ~2^760 with p-1 = 2 * (product of distinct
# ~2^21 primes), generated so that S is a primitive root mod p. Then
#   * mod 256: S = 2*odd  =>  S^e ≡ 0 (mod 256) for every e >= 8 — so any claim
#     whose padded digest ends in a 0x00 byte qualifies. The last digest byte is
#     the last hash byte, so message freedom makes this a ~1/256 search.
#   * mod p: ord(S) = p-1 is smooth, so e_i = dlog_S(T_i) falls to Pohlig-Hellman
#     + BSGS; bump by p-1 if needed so e_i >= 8.
#   CRT: pow(S, e_i, n) == T_i exactly, since T_i < 2^753 < n.
# The deployed emsa_pkcs1_v15 hashed with SHA-1 in part 1 despite importing
# SHA256, so the digest format is probed (sha1/sha256) on the first claim.

import socket, json, hashlib, random, string, os, sys, tempfile
from math import isqrt

HOST, PORT = "socket.cryptohack.org", 13394
K = 96                                    # padded digest size (768-bit key)
FLAG_LEN = 48

FMTS = [                                  # (name, hash, DigestInfo prefix)
    ("sha1",   hashlib.sha1,   bytes.fromhex("3021300906052b0e03021a05000414")),
    ("sha256", hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
]

def padded_T(msg, prefix, hf):
    d = prefix + hf(msg).digest()
    return int.from_bytes(b"\x00\x01" + b"\xff" * (K - len(d) - 3) + b"\x00" + d, "big")

# ---------------------------------------------------------------- smooth prime
def is_probable_prime(n, rounds=20):
    if n < 2: return False
    for q in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % q == 0: return n == q
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True

def sieve_primes(lo, hi):
    sieve = bytearray([1]) * (hi - lo)
    for q in range(2, isqrt(hi) + 1):
        start = max(q * q, ((lo + q - 1) // q) * q)
        sieve[start - lo::q] = bytearray(len(sieve[start - lo::q]))
    out = []
    for i, b in enumerate(sieve):
        if b and lo + i >= 2: out.append(lo + i)
    return out

def gen_params(S, cache=None):
    if cache and os.path.exists(cache):
        p, fs = json.load(open(cache))
        if pow(S % p, (p - 1) // 2, p) != 1 and S % p != 0:
            return p, fs
    pool = sieve_primes(1 << 20, 1 << 21)
    print(f"[*] generating smooth-1 prime (~68k pool)...")
    while True:
        fs, used, E = [], set(), 1
        for _ in range(37):
            l = random.choice(pool)
            if l in used: continue
            used.add(l); fs.append(l); E *= l
        if not (1 << 756 <= E < 1 << 762): continue
        p = 2 * E + 1
        if not is_probable_prime(p): continue
        if S % p == 0: continue
        # S must be a primitive root: S^((p-1)/l) != 1 for every prime l | p-1
        if pow(S, (p - 1) // 2, p) == 1: continue
        if any(pow(S, (p - 1) // l, p) == 1 for l in fs): continue
        if cache: json.dump([p, fs], open(cache, "w"))
        return p, fs

# ------------------------------------------------- Pohlig-Hellman dlog mod p
class Dlog:
    def __init__(self, S, p, odd_factors):
        self.p = p
        self.ls = odd_factors + [2]        # p-1 = 2 * prod(odd), all distinct primes
        self.tabs = {}
        for l in self.ls:
            g0 = pow(S, (p - 1) // l, p)   # order exactly l
            m = isqrt(l) + 1
            tbl, cur = {}, 1
            for j in range(m):
                tbl[cur] = j
                cur = cur * g0 % p
            self.tabs[l] = (tbl, pow(g0, l - m, p), m)
        # self-test on a random unit
        y = random.randrange(2, p - 1) | 1
        assert pow(S, self.dlog(y), p) == y % p, "PH self-test failed"

    def dlog(self, h):
        xs, ms = [], []
        for l in self.ls:
            tbl, gstep, m = self.tabs[l]
            h0 = pow(h, (self.p - 1) // l, self.p)
            x, cur = None, h0
            for i in range(m):
                j = tbl.get(cur)
                if j is not None:
                    x = (i * m + j) % l
                    break
                cur = cur * gstep % self.p
            assert x is not None, "dlog failed"
            xs.append(x); ms.append(l)
        e, M = 0, 1
        for x, l in zip(xs, ms):
            e += M * ((x - e) * pow(M, -1, l) % l)
            M *= l
        return e

# ---------------------------------------------------------------- connection
def recv_json(s):
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk: raise EOFError
        buf += chunk
        try: return json.loads(buf)
        except json.JSONDecodeError:
            if buf.endswith(b"\n"): buf = b""   # drop plain-text banner line

def query(s, obj):
    s.sendall(json.dumps(obj).encode() + b"\n")
    return recv_json(s)

# ------------------------------------------------------------- message fodder
ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(raw):
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHA[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out

def btc_address():
    payload = b"\x00" + os.urandom(20)
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)

def gen0(suffix):
    i = 0
    while True:
        yield "This is a test" + f"{i:06x}" + "for a fake signature." + suffix
        i += 1

def gen1(suffix):
    while True:
        name = "Alice " + "".join(random.choice(string.ascii_letters) for _ in range(10))
        yield "My name is " + name + " and I own CryptoHack.org" + suffix

def gen2(suffix):
    while True:
        yield "Please send all my money to " + btc_address() + suffix

GENS = [gen0, gen1, gen2]

PATTERNS = [
    lambda m: __import__("re").match(r"^This is a test(.*)for a fake signature.$", m),
    lambda m: __import__("re").match(r"^My name is ([a-zA-Z\s]+) and I own CryptoHack.org$", m),
    None,   # btc check replicated minimally: last digest byte condition is what we search on
]

def solve_claim(idx, suffix, dl, S, n, p, s, fmt_lock):
    fmts = [fmt_lock] if fmt_lock else [f[0] for f in FMTS]
    fmap = {f[0]: (f[1], f[2]) for f in FMTS}
    attempts = 0
    for msg in GENS[idx](suffix):
        attempts += 1
        if attempts > 20000:
            raise RuntimeError(f"claim {idx}: no qualifying message after {attempts} tries")
        stem = msg[: -len(suffix)]
        if idx < 2 and not PATTERNS[idx](stem): continue
        if idx == 2 and not stem.startswith("Please send all my money to "): continue
        for fmt in fmts:
            hf, prefix = fmap[fmt]
            T = padded_T(msg.encode(), prefix, hf)
            if T % 256: continue                     # need last digest byte 0x00
            e = dl.dlog(T)
            if e < 8: e += (p - 1)                   # ensure S^e ≡ 0 (mod 256)
            assert pow(S, e, n) == T, "local CRT check failed"
            r = query(s, {"option": "claim", "msg": msg, "e": hex(e), "index": idx})
            if "secret" in r:
                return bytes.fromhex(r["secret"]), fmt
            if r.get("error") and r["error"] != "Invalid signature":
                print("[!]", r)
    raise RuntimeError(f"claim {idx} exhausted")

def xor3(a, b, c):
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))

def main():
    s = socket.create_connection((HOST, PORT), timeout=60)
    s.settimeout(60)
    S = int(query(s, {"option": "get_signature"})["signature"], 16)
    print(f"[*] S: {S.bit_length()} bits (S ≡ {S % 8} mod 8)")

    cache = os.path.join(tempfile.gettempdir(), "lda_smooth_p.json")
    p, fs = gen_params(S, cache)
    n = p * 256
    print(f"[*] fake pubkey n = p*256, p: {p.bit_length()} bits, p-1 = 2*{len(fs)} smooth primes")

    r = query(s, {"option": "set_pubkey", "pubkey": hex(n)})
    assert r.get("status") == "ok", r
    suffix = r["suffix"]
    print(f"[*] suffix: {suffix}")

    dl = Dlog(S, p, fs)
    shares, fmt_lock = [], None
    for idx in range(3):
        share, fmt_lock = solve_claim(idx, suffix, dl, S, n, p, s, fmt_lock)
        shares.append(share)
        print(f"[*] share {idx} collected (digest format: {fmt_lock})")
    s.close()

    print("[+] FLAG:", xor3(*shares).decode())

if __name__ == "__main__":
    main()
