import json
import hashlib
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_params(path="params.json"):
    data = json.load(open(path))
    N = int(data["N"])
    e = int(data["e"])
    ct = bytes.fromhex(data["encrypted_flag"])
    nonce = bytes.fromhex(data["nonce"])
    tag = bytes.fromhex(data["tag"])
    S = int(data["leakage2"]["S"])
    return N, e, ct, nonce, tag, S


def wiener_attack(N, e):
    """Recover d, p, q from (N, e) using Wiener's continued-fraction attack."""

    def continued_fraction(num, den):
        cf = []
        while den:
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
        return cf

    def convergents(cf):
        n0, n1 = 0, 1
        d0, d1 = 1, 0
        for a in cf:
            n2 = a * n1 + n0
            d2 = a * d1 + d0
            yield n2, d2
            n0, n1 = n1, n2
            d0, d1 = d1, d2

    cf = continued_fraction(e, N)
    for k, d in convergents(cf):
        if k == 0:
            continue
        phi_candidate = (e * d - 1) // k
        s = N - phi_candidate + 1               # p + q
        disc = s * s - 4 * N
        if disc > 0:
            t = isqrt(disc)
            if t * t == disc:
                p = (s + t) // 2
                q = (s - t) // 2
                if p * q == N:
                    return d, p, q
    raise RuntimeError("Wiener attack failed")


def derive_aes_key(d, S, lambda_n):
    d_bytes = long_to_bytes(d)
    V_int = d_bytes[:16]
    H1 = hashlib.sha256(V_int).digest()
    H2 = hashlib.sha256(long_to_bytes(S)).digest()
    H3 = hashlib.sha256(long_to_bytes(lambda_n)).digest()
    IKM = H1 + H2 + H3

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"FastLane-RSA-2024",
        info=b"FastLane-AES-Key",
    )
    return hkdf.derive(IKM)


def main():
    N, e, ct, nonce, tag, S = load_params()

    d, p, q = wiener_attack(N, e)
    print(f"[+] d = {d}")
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")

    lambda_n = (p - 1) * (q - 1) // gcd(p - 1, q - 1)

    aes_key = derive_aes_key(d, S, lambda_n)
    print(f"[+] AES key = {aes_key.hex()}")

    flag = AESGCM(aes_key).decrypt(nonce, ct + tag, None)
    print(f"[+] FLAG = {flag.decode()}")

    return flag.decode()


if __name__ == "__main__":
    main()
