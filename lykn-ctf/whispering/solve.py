#!/usr/bin/env python3
"""
LYKNCTF 2026 — Whispering (Crypto) — Solve Script

Recovers the AES encryption key from side-channel leakage of the NTRU
private polynomials' coefficient sums, then decrypts the flag.
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import unpad
import requests
import sys


def recover_actual(mod_val: int, max_abs: int) -> int:
    """Recover the actual integer sum from its value mod 127."""
    if mod_val <= max_abs:
        return mod_val
    return mod_val - 127


def solve(server_url: str) -> str:
    # Step 1 — Fetch data from the server
    pub = requests.get(f"{server_url}/public.json").json()
    side = requests.get(f"{server_url}/side_channel.json").json()

    params = pub["parameters"]
    N = params["N"]
    q = params["q"]
    q_prime = params["q_prime"]

    ct_hex = pub["encrypted_flag"]["ciphertext"]
    iv_hex = pub["encrypted_flag"]["iv"]
    salt = pub["encrypted_flag"]["salt"]

    f_even = side["constraints"]["f_even_sum_mod_127"]
    f_odd  = side["constraints"]["f_odd_sum_mod_127"]
    g_even = side["constraints"]["g_even_sum_mod_127"]
    g_odd  = side["constraints"]["g_odd_sum_mod_127"]

    # Step 2 — Recover exact coefficient sums from mod-127 residues
    f_even_act = recover_actual(f_even, 64)
    f_odd_act  = recover_actual(f_odd, 63)
    g_even_act = recover_actual(g_even, 64)
    g_odd_act  = recover_actual(g_odd, 63)

    sum_f = f_even_act + f_odd_act
    sum_g = g_even_act + g_odd_act

    print(f"[*] Recovered sums: sum_f = {sum_f}, sum_g = {sum_g}")

    # Step 3 — Compute the algebraic signature V
    # V = Σ_k (f * g)[k]  =  (Σ_i f[i]) · (Σ_j g[j])   (mod q_prime)
    V = (sum_f * sum_g) % q_prime
    print(f"[*] Algebraic signature V = {V}")

    # Step 4 — Derive the AES-256 key (same as server-side HKDF)
    ikm = (
        V.to_bytes(4, "big")
        + N.to_bytes(2, "big")
        + q.to_bytes(2, "big")
        + salt.encode("utf-8")
    )

    key = HKDF(
        master=ikm,
        key_len=32,
        salt=str(N).encode("utf-8"),
        hashmod=SHA256,
    )

    # Step 5 — Decrypt the flag
    ct = bytes.fromhex(ct_hex)
    iv = bytes.fromhex(iv_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    flag = unpad(cipher.decrypt(ct), AES.block_size).decode()

    print(f"[+] Flag: {flag}")
    return flag


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <server_url>")
        print(f"Example: {sys.argv[0]} http://db9c3975-d3e7-4db6-bd74-3a509bdb8605.51.79.140.18.nip.io:8080")
        sys.exit(1)
    solve(sys.argv[1])
