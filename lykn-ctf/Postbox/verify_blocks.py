"""
Verify all blocks quickly against a new instance.
"""
import requests, time, sys

def oracle(base, iv_hex, ct_hex):
    try:
        r = requests.post(f"{base}/decrypt", json={"iv": iv_hex, "ciphertext": ct_hex}, timeout=10)
        if r.status_code == 200:
            return r.json().get("ok") is True
    except:
        pass
    return False

def recover_block(base, prev_hex, ct_block_hex, label):
    prev = bytes.fromhex(prev_hex)
    inter = bytearray(16)
    for pos in range(15, -1, -1):
        pad = 16 - pos
        found = None
        for g in range(256):
            tweak = bytearray(16)
            for j in range(pos + 1, 16):
                tweak[j] = inter[j] ^ pad
            tweak[pos] = g
            if oracle(base, tweak.hex(), ct_block_hex):
                found = g
                break
        if found is not None:
            inter[pos] = found ^ pad
            ch = chr(inter[pos]) if 32 <= inter[pos] < 127 else f"\\x{inter[pos]:02x}"
            print(f"[{label}] byte {pos:2d}: '{ch}'")
        else:
            print(f"[{label}] byte {pos:2d}: NO MATCH")
            inter[pos] = 0
    pt = bytes(a ^ b for a, b in zip(prev, inter))
    print(f"[{label}] hex: {pt.hex()}")
    print(f"[{label}] str: {pt.decode(errors='replace')}")
    return pt

if len(sys.argv) < 2:
    print("Usage: python3 verify_blocks.py <base_url>")
    sys.exit(1)

BASE = sys.argv[1]

# Get token
r = requests.get(f"{BASE}/login")
d = r.json()
IV = d["iv"]
CT = d["ciphertext"]
print(f"IV: {IV}")
print(f"CT: {CT}")

ct = bytes.fromhex(CT)
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
print(f"\n{len(blocks)} blocks\n")

results = []
for i, block in enumerate(blocks):
    prev = IV if i == 0 else blocks[i-1].hex()
    print(f"--- Block {i} ---")
    pt = recover_block(BASE, prev, block.hex(), f"B{i}")
    results.append(pt)
    print()

plaintext = b"".join(results)
p = plaintext[-1]
if 1 <= p <= 16 and plaintext[-p:] == bytes([p] * p):
    plaintext = plaintext[:-p]

print(f"=== Full plaintext ({len(plaintext)} bytes) ===")
print(plaintext.decode(errors='replace'))
