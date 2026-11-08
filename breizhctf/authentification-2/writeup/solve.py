import sys, re, json, requests
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcmforge as G

URL = "http://archive.cryptohack.org:59670"
username, password = "A"*10, "x"

def dequote(v):
    if v.startswith('"') and v.endswith('"'): v = v[1:-1]
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1),8)), v).replace('\\\\','\\')

s = requests.Session()
s.get(f"{URL}/reset-db")
s.post(f"{URL}/register", data={"username":username,"password":password}, allow_redirects=False)
r = s.post(f"{URL}/login", data={"username":username,"password":password}, allow_redirects=False)
raw = dequote(r.cookies["auth"])
ct_hex, tag_hex = raw.split(";")
C_guest, T_guest = bytes.fromhex(ct_hex), bytes.fromhex(tag_hex)
P_guest = json.dumps({"username":username,"role":"guest"}).encode()
print(f"[*] guest token recovered: ct={len(C_guest)}B tag={len(T_guest)}B pt_len={len(P_guest)}")

EJ0, Hs = G.recover_H_candidates(C_guest, T_guest, P_guest)
print(f"[*] recovered {len(Hs)} candidate H value(s)")
target = json.dumps({"username":"a","role":"super_admin"}).encode()
for i, H in enumerate(Hs):
    token = G.forge(C_guest, P_guest, EJ0, H, target)
    page = s.get(f"{URL}/admin", headers={"Cookie": f'auth="{token}"'}).text
    m = re.search(r"BZHCTF\{[^}]*\}", page)
    if m:
        print(f"[*] candidate {i}: ACCEPTED")
        print("FLAG:", m.group(0)); break
    else:
        why = "not super_admin" if "not super_admin" in page.lower() else ("bad token" if "Error with the token" in page else "no flag")
        print(f"[*] candidate {i}: {why}")
