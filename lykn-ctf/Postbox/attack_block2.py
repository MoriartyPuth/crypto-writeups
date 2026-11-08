"""
Recover block 2 to verify the flag prefix.
"""
import requests, time

BASE = "http://054bf5a0-3ac6-45cb-a470-fff233761ee6.51.79.140.18.nip.io:8080"

def oracle(iv_hex, ct_hex):
    try:
        r = requests.post(f"{BASE}/decrypt", json={"iv": iv_hex, "ciphertext": ct_hex}, timeout=10)
        if r.status_code == 200:
            return r.json().get("ok") is True
    except:
        pass
    return False

prev_hex = "0b329323a830f821b8aae00001580b74"  # block 1
ct_hex = "75894bfbb36bc2b63e8607b200b9324c"  # block 2

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
        if oracle(tweak.hex(), ct_hex):
            found = g
            break
    dt = time.time() - t0
    if found is not None:
        inter[pos] = found ^ pad
        ch = chr(inter[pos]) if 32 <= inter[pos] < 127 else f"\\x{inter[pos]:02x}"
        print(f"byte {pos:2d}/15: 0x{found:02x} -> '{ch}' [{16-pos}/16] {dt:.1f}s")
    else:
        print(f"byte {pos:2d}/15: NO MATCH [{16-pos}/16] {dt:.1f}s")

pt = bytes(a ^ b for a, b in zip(prev, inter))
print(f"\nBlock 2 hex: {pt.hex()}")
print(f"Block 2 str: {pt.decode(errors='replace')}")
