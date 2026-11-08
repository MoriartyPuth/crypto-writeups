import socket, base64, gzip, re, sys, os, time
from ast import literal_eval
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lll import bdd_norm

HOST,PORT="archive.cryptohack.org",43607
q=8380417; k,l=8,7
THRESH=1000

def decode(s):
    return literal_eval(gzip.decompress(base64.b64decode(s)).decode())

s=socket.create_connection((HOST,PORT),timeout=30)
buf=b""
def recv_until(tok=b"> "):
    global buf
    while tok not in buf:
        d=s.recv(65536)
        if not d:               # EOF: server exited (e.g. after printing flag)
            seg=buf; buf=b""
            return seg.decode(errors="replace")
        buf+=d
    i=buf.find(tok)+len(tok)
    chunk=buf[:i]; buf=buf[i:]
    return chunk.decode(errors="replace")

round_no=0
def check_flag(seg):
    m=re.search(r"BZHCTF\{[^}]*\}",seg)
    if m or "Well played, here is the flag" in seg:
        print("FLAG:", m.group(0) if m else seg.strip()[-200:])
        return True
    return False

while True:
    seg=recv_until()
    if check_flag(seg): break
    mA=re.search(r"sanitize_mat\(A\) = '([^']+)'",seg)
    mt=re.search(r"sanitize_vec\(t\) = '([^']+)'",seg)
    if not (mA and mt):
        if not seg.strip():  # connection closed / empty
            break
        continue
    A=decode(mA.group(1)); t=decode(mt.group(1))
    # evaluate at x=1: sum of coeffs mod q
    A1=[[sum(A[r][c])%q for c in range(l)] for r in range(k)]
    t1=[sum(t[r])%q for r in range(k)]
    norm=bdd_norm(A1,t1,q)
    ans="1" if norm<THRESH else "0"
    s.sendall((ans+"\n").encode())
    round_no+=1
    # read the wp/oups feedback (it precedes next prompt, but grab quickly)
    print(f"round {round_no}: norm={norm:8.1f} -> {ans}")
    sys.stdout.flush()
s.close()
