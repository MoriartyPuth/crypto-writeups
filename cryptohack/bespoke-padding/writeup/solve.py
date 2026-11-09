import socket, json, sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fr import franklin_reiter

HOST,PORT="socket.cryptohack.org",13386
s=socket.create_connection((HOST,PORT),timeout=30)
f=s.makefile("rwb",buffering=0)

def readjson():
    while True:
        line=f.readline()
        if not line: raise EOFError
        line=line.strip()
        if not line: continue
        try: return json.loads(line)
        except json.JSONDecodeError: continue   # skip banner text

def query():
    f.write(json.dumps({"option":"get_flag"}).encode()+b"\n")
    return readjson()

r1=query(); r2=query()
a1,b1=r1["padding"]; c1=r1["encrypted_flag"]; N=r1["modulus"]
a2,b2=r2["padding"]; c2=r2["encrypted_flag"]
print(f"[*] N bits={N.bit_length()}  e=11  two queries captured")
m=franklin_reiter(a1,b1,c1,a2,b2,c2,11,N)
flag=m.to_bytes((m.bit_length()+7)//8,"big")
print("FLAG:", flag.decode(errors="replace"))
s.close()
