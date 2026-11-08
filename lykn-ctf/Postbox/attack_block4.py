"""
Recover block 4 (the last content block) to verify.
"""
import requests
import time

BASE = "http://054bf5a0-3ac6-45cb-a470-fff233761ee6.51.79.140.18.nip.io:8080"

def oracle(iv_hex, ct_hex):
    try:
        r = requests.post(f"{BASE}/decrypt", json={"iv": iv_hex, "ciphertext": ct_hex}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return data.get("ok") is True
    except:
        pass
    return False

prev_hex = "46a36d43fc990556cb39474f6d6a8382"
ct_block_hex = "a2eea270d9dae2e97cc84d02d4fcdb0a"

prev = bytes.fromhex(prev_hex)
inter = bytearray(16)

for pos in range(15, -1, -1):
    pad = 16 - pos
    t0 = time.time()
    found = None
    for g in range(256):
        tweak = bytearray(16)
        for j in range(pos + 1, 16):
            tweak[j] = inter[j] ^ pad
        tweak[pos] = g
        if oracle(tweak.hex(), ct_block_hex):
            found = g
            break
    dt = time.time() - t0
    if found is not None:
        inter[pos] = found ^ pad
        ch = chr(inter[pos]) if 32 <= inter[pos] < 127 else f"\\x{inter[pos]:02x}"
        print(f"byte {pos:2d}/15: 0x{found:02x} -> '{ch}' [{16-pos}/16] {dt:.1f}s")
    else:
        print(f"byte {pos:2d}/15: NO MATCH [{16-pos}/16] {dt:.1f}s")

plaintext = bytes(a ^ b for a, b in zip(prev, inter))
print(f"\nBlock 4 plaintext hex: {plaintext.hex()}")
print(f"Block 4 plaintext str: {plaintext.decode(errors='replace')}")
