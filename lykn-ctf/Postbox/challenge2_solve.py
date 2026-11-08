"""
Postbox - Padding Oracle Attack
LYKNCTF 2026

Async with semaphore-limited concurrency. Fast and reliable.
"""

import asyncio
import aiohttp
import re
import time

BASE = "http://fb1bc76f-2c55-43ed-a16e-f7302e3e591a.51.79.140.18.nip.io:8080"
CONCURRENCY = 32  # max simultaneous requests


async def oracle(session, sem, iv_hex, ct_hex):
    async with sem:
        try:
            async with session.post(
                f"{BASE}/decrypt",
                json={"iv": iv_hex, "ciphertext": ct_hex},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status != 200:
                    return False
                data = await r.json()
                return data.get("ok") is True
        except:
            return False


async def find_byte(session, sem, ct_block_hex, inter, pos):
    pad = 16 - pos
    for batch_start in range(0, 256, CONCURRENCY):
        batch_end = min(batch_start + CONCURRENCY, 256)

        async def try_one(g):
            tweak = bytearray(16)
            for j in range(pos + 1, 16):
                tweak[j] = inter[j] ^ pad
            tweak[pos] = g
            ok = await oracle(session, sem, tweak.hex(), ct_block_hex)
            return g, ok

        tasks = [try_one(g) for g in range(batch_start, batch_end)]
        results = await asyncio.gather(*tasks)

        for g, ok in results:
            if ok:
                return g

    return None


async def recover_block(session, sem, prev_hex, ct_block_hex, label):
    prev = bytes.fromhex(prev_hex)
    inter = bytearray(16)

    for pos in range(15, -1, -1):
        t0 = time.time()
        found = await find_byte(session, sem, ct_block_hex, inter, pos)
        dt = time.time() - t0

        if found is not None:
            inter[pos] = found ^ (16 - pos)
            done = 16 - pos
            found_text = f"0x{found:02x}"
        else:
            found_text = "NO MATCH"

        done = 16 - pos
        print(f"  [{label}] byte {pos:2d}/15: {found_text} [{done}/16] {dt:.1f}s", flush=True)

    return bytes(a ^ b for a, b in zip(prev, inter))


async def main():
    print("[*] Getting token...", flush=True)
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{BASE}/login") as r:
            d = await r.json()
            iv_hex, ct_hex = d["iv"], d["ciphertext"]

    print(f"  IV: {iv_hex}\n  CT: {ct_hex}", flush=True)

    ct = bytes.fromhex(ct_hex)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    print(f"[*] {len(blocks)} blocks\n", flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        pts = []
        for i, block in enumerate(blocks):
            prev = iv_hex if i == 0 else blocks[i-1].hex()
            print(f"--- Block {i}/{len(blocks)-1} ---", flush=True)
            pt = await recover_block(session, sem, prev, block.hex(), f"B{i}")
            pts.append(pt)
            print(f"  raw: {pt}\n", flush=True)

    plaintext = b"".join(pts)
    p = plaintext[-1]
    if 1 <= p <= 16 and plaintext[-p:] == bytes([p] * p):
        plaintext = plaintext[:-p]

    text = plaintext.decode(errors="replace")
    print(f"\n[+] Plaintext ({len(plaintext)} bytes): {text}", flush=True)

    for pat in [r"LYKNCTF\{[^}]+\}", r"flag\{[^}]+\}", r"FLAG\{[^}]+\}"]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            print(f"[+] FLAG: {m.group()}", flush=True)
            return


if __name__ == "__main__":
    asyncio.run(main())
