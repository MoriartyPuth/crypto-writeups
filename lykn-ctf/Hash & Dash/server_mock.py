#!/usr/bin/env python3
"""
Faithful local reproduction of LYKNCTF "Hash & Dash" (crypto, beginner).

Prompt: "A tiny access-token service is waiting for your request. You are
given a valid guest token. Your goal is to submit a valid token for a
message that grants admin access."

The remote instance (nc 51.79.140.18 15787) was a time-boxed CTF instance
("Remaining Time: 594s") and has since expired, so this is a from-scratch
mock built to match the prompt's described behavior exactly: a MAC built as
H(secret || message) instead of a real HMAC, over a Merkle-Damgard hash
(SHA-256) - the textbook length-extension setup. It's used here to build
and verify the real exploit end-to-end.
"""
import hashlib
import os
import socketserver

SECRET = os.urandom(16)          # unknown to the client, fixed per server run
GUEST_MSG = b"user=guest&admin=false"


def mac(msg: bytes) -> str:
    return hashlib.sha256(SECRET + msg).hexdigest()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"=== Tiny Access-Token Service ===\n")
        self.wfile.write(b"Your guest token:\n")
        self.wfile.write(b"msg=" + GUEST_MSG + b"\n")
        self.wfile.write(b"tok=" + mac(GUEST_MSG).encode() + b"\n\n")
        self.wfile.write(b"Send: <hex message>:<hex token>\n> ")
        self.wfile.flush()

        line = self.rfile.readline().strip()
        try:
            hexmsg, hextok = line.split(b":")
            msg = bytes.fromhex(hexmsg.decode())
            tok = hextok.decode()
        except Exception:
            self.wfile.write(b"bad format\n")
            self.wfile.flush()
            return

        if tok != mac(msg):
            self.wfile.write(b"invalid token\n")
            self.wfile.flush()
            return
        if b"admin=true" not in msg:
            self.wfile.write(b"valid token, but no admin claim - guest only\n")
            self.wfile.flush()
            return
        self.wfile.write(b"ADMIN ACCESS GRANTED: LYKNCTF{local_test_flag_only}\n")
        self.wfile.flush()


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 27391
    with socketserver.TCPServer((HOST, PORT), Handler) as srv:
        srv.allow_reuse_address = True
        print(f"[*] listening on {HOST}:{PORT}, secret len={len(SECRET)} (unknown to client)")
        srv.serve_forever()
