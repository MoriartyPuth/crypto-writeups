"""
Noisy Broadcast — LYKNCTF 2026
Solution: Bit-wise majority voting on three noisy copies of m^3, then cube root.
"""

import gmpy2
from gmpy2 import mpz

# ========== Challenge Data ==========
e = 3

n1 = mpz(85228226732724847418067455743651142740476746995496551792634288054845497526120574520236279086740384492847733992149243642754289284545794328756970055580180294263535347412397459623691770532411325493069012460763918948201718038800689837937367866477998560124253040344625160586858409297252280344867998951473281810743)
c1 = mpz(258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925590879169419712047717)

n2 = mpz(97924666516843498160783101526130849604538813870081628922966609409449321121847131831281164670048951543379388432910134367882183266056444104250973101721344279684158309956009160730977339135393546720115388599622212761223476162768735295507584925036626029099233722497358026365940231114743083815647181152118332887931)
c2 = mpz(258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925590874661422038166117)

n3 = mpz(103096857448251887075257488004365940130545594057545157206836240630382407265637562317282373470695808990568775619043712493052636484505313305983891665885277023257298661110365836476991553181927650311887693236012437409897450200217448177064588660793633185238057210041784341180033593395853297481864041793470140461977)
c3 = mpz(258513173341110907855004634578328776675613337727374937778021308566776511394028586169719647601517686407530370600703671047834514223488817495300633613007122903215194800830817082508335094056353114537752319982589386027924378028160153097890317313131416661071211651623002925295726760640731851365)


# ========== Step 1: Analyse the ciphertexts ==========

s1, s2, s3 = str(c1), str(c2), str(c3)
print(f"[*] c1 length: {len(s1)} digits")
print(f"[*] c2 length: {len(s2)} digits")
print(f"[*] c3 length: {len(s3)} digits")

# Find common prefix (where all three agree)
i = 0
while i < len(s1) and s1[i] == s2[i] == s3[i]:
    i += 1
print(f"[*] Common prefix: {i} digits")
print(f"[*] Differing suffix: {len(s1) - i} digits")

# Show the differing suffixes
print(f"\n[*] c1 suffix: {s1[i:]}")
print(f"[*] c2 suffix: {s2[i:]}")
print(f"[*] c3 suffix: {s3[i:]}")


# ========== Step 2: Bit-wise majority voting ==========

print("\n[*] Performing bit-wise majority voting...")

b1 = bin(c1)[2:]
b2 = bin(c2)[2:]
b3 = bin(c3)[2:]

max_bits = max(len(b1), len(b2), len(b3))
b1 = b1.zfill(max_bits)
b2 = b2.zfill(max_bits)
b3 = b3.zfill(max_bits)

majority_bits = ''
for pos in range(max_bits):
    ones = int(b1[pos]) + int(b2[pos]) + int(b3[pos])
    majority_bits += '1' if ones >= 2 else '0'

c_maj = int(majority_bits, 2)
print(f"[*] Majority result: {c_maj}")
print(f"[*] Majority bit length: {c_maj.bit_length()} bits")


# ========== Step 3: Cube root ==========

print("\n[*] Taking integer cube root...")

root, exact = gmpy2.iroot(mpz(c_maj), e)
print(f"[*] Exact cube: {exact}")

if not exact:
    print("[!] Not a perfect cube — trying alternative approaches...")
    # Fallback: try CRT with the majority c value
    N = n1 * n2 * n3
    N1, N2, N3 = N // n1, N // n2, N // n3
    inv1 = gmpy2.invert(N1, n1)
    inv2 = gmpy2.invert(N2, n2)
    inv3 = gmpy2.invert(N3, n3)
    x = (mpz(c_maj) * N1 * inv1 + mpz(c_maj) * N2 * inv2 + mpz(c_maj) * N3 * inv3) % N
    root, exact = gmpy2.iroot(x, e)
    print(f"[*] CRT + cube root exact: {exact}")


# ========== Step 4: Decode ==========

if exact:
    m_bytes = root.to_bytes((root.bit_length() + 7) // 8, 'big')
    flag = m_bytes.decode(errors='replace')
    print(f"\n[+] FLAG: {flag}")
else:
    print("\n[-] Could not recover exact cube. Trying nearby values...")
    # Broader search: try enumerating suffix combinations
    c_values = [c1, c2, c3]
    for c in c_values:
        r, ok = gmpy2.iroot(c, 3)
        if ok:
            m_bytes = r.to_bytes((r.bit_length() + 7) // 8, 'big')
            print(f"[+] Direct cube of c: {m_bytes}")
