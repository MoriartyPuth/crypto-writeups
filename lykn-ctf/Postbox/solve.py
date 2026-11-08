#!/usr/bin/env python3
"""
Postbox — Padding Oracle Attack
LYKNCTF 2026
Usage: python3 solve.py <instance_url>
Example: python3 solve.py http://054bf5a0-3ac6-45cb-a470-fff233761ee6.51.79.140.18.nip.io:8080
"""

import asyncio
import aiohttp
import re
import sys
import time

CONCURRENCY = 40


async def oracle(session, sem, base, iv_hex, ct_hex):
    """Query the padding oracle. Returns True if padding is valid."""
    async with sem:
        try:
            async with session.post(
                f"{base}/decrypt",
                json={"iv": iv_hex, "ciphertext": ct_hex},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("ok") is True
        except Exception:
            pass
        return False


async def find_byte(session, sem, base, ct_block_hex, inter, pos):
    """
    Find the intermediate value byte at `pos` by trying all 256 guesses
    in parallel batches until the oracle says the padding is valid.
    """
    pad = 16 - pos
    for batch_start in range(0, 256, CONCURRENCY):
        batch_end = min(batch_start + CONCURRENCY, 256)

        async def try_one(g):
            tweak = bytearray(16)
            for j in range(pos + 1, 16):
                tweak[j] = inter[j] ^ pad
            tweak[pos] = g
            ok = await oracle(session, sem, base, tweak.hex(), ct_block_hex)
            return g, ok

        tasks = [try_one(g) for g in range(batch_start, batch_end)]
        results = await asyncio.gather(*tasks)

        for g, ok in results:
            if ok:
                return g

    return None


async def recover_block(session, sem, base, prev_hex, ct_block_hex, label):
    """Recover one plaintext block using the padding oracle."""
    prev = bytes.fromhex(prev_hex)
    inter = bytearray(16)

    for pos in range(15, -1, -1):
        t0 = time.time()
        found = await find_byte(session, sem, base, ct_block_hex, inter, pos)
        dt = time.time() - t0

        if found is not None:
            inter[pos] = found ^ (16 - pos)
            ch = chr(inter[pos]) if 32 <= inter[pos] < 127 else f"\\x{inter[pos]:02x}"
            print(f"  [{label}] pos {pos:2d}: 0x{found:02x} -> {ch}  [{16-pos}/16] {dt:.1f}s", flush=True)
        else:
            print(f"  [{label}] pos {pos:2d}: NO MATCH  [{16-pos}/16] {dt:.1f}s", flush=True)
            inter[pos] = 0

    pt = bytes(a ^ b for a, b in zip(prev, inter))
    print(f"  [{label}] hex: {pt.hex()}  str: {pt.decode(errors='replace')}", flush=True)
    return pt


async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <instance_url>")
        print(f"Example: {sys.argv[0]} http://<uuid>.51.79.140.18.nip.io:8080")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")

    # Step 1: Get the token
    print("[*] Fetching token...", flush=True)
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/login") as r:
            d = await r.json()
            iv_hex, ct_hex = d["iv"], d["ciphertext"]

    print(f"  IV: {iv_hex}")
    print(f"  CT: {ct_hex}", flush=True)

    ct = bytes.fromhex(ct_hex)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    print(f"\n[*] {len(blocks)} blocks\n", flush=True)

    # Step 2: Attack all blocks concurrently
    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, block in enumerate(blocks):
            prev = iv_hex if i == 0 else blocks[i-1].hex()
            print(f"--- Block {i} ---", flush=True)
            tasks.append(recover_block(session, sem, base, prev, block.hex(), f"B{i}"))
        results = await asyncio.gather(*tasks)

    # Step 3: Concatenate and strip padding
    plaintext = b"".join(results)
    p = plaintext[-1]
    if 1 <= p <= 16 and plaintext[-p:] == bytes([p] * p):
        plaintext = plaintext[:-p]

    text = plaintext.decode(errors="replace")
    print(f"\n[+] Plaintext ({len(plaintext)} bytes): {text}", flush=True)

    # Step 4: Extract flag
    for pat in [r"LYKNCTF\{[^}]+\}", r"flag\{[^}]+\}", r"FLAG\{[^}]+\}"]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            print(f"[+] FLAG: {m.group()}", flush=True)
            return

    print("[-] No flag pattern found in plaintext", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
