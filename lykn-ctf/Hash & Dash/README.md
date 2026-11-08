# Hash & Dash (crypto, beginner)

**Flag:** obtained via the technique below against the live instance
(`51.79.140.18:15787`, since expired — CTF instances were time-boxed,
"Remaining Time: 594s" at issue time).

> A tiny access-token service is waiting for your request. You are given a
> valid guest token. Your goal is to submit a valid token for a message
> that grants admin access.

## The design flaw

The service authenticates a message with:

```
token = SHA256(secret || message).hexdigest()
```

instead of a real MAC (HMAC). SHA-256, like MD5/SHA-1, is a
**Merkle–Damgård** hash: its 256-bit output *is* the entire internal
compression state after absorbing all input so far. Handed a valid
`(message, token)` pair, an attacker can resume compression from that
state and keep hashing — appending arbitrary attacker-chosen bytes —
**without ever learning `secret`**, as long as they know (or can guess)
`len(secret)`.

This is the textbook **hash length-extension attack**.

## Building the forged request

Given `guest_msg = b"user=guest&admin=false"` and its token:

1. Compute SHA-256's own padding for `secret_len + len(guest_msg)` bytes —
   this "glue" is what the real hash function would have appended before
   compressing the next block. It must sit between the original message
   and whatever we append.
2. Re-seed a from-scratch SHA-256 compression loop with the state decoded
   from the known token's hex digest.
3. Feed it our appended data (`b"&admin=true"`) as if it were simply the
   next block(s) of the original message.
4. Submit `forged_msg = guest_msg + glue + b"&admin=true"` together with
   the newly computed digest.

The server, none the wiser, computes `SHA256(secret || forged_msg)`
internally — which is now genuinely correct, because `forged_msg` is
exactly what the real hash function would have processed had `secret ||
guest_msg || glue || "&admin=true"` been the original input.

`exploit.py` reimplements the SHA-256 compression function directly in
pure Python (no `hashpump`/C extension dependency) so it can be resumed
from an arbitrary mid-state — see `_compress`/`_sha256_from_state`.

### The one unknown: secret length

`len(secret)` isn't given, so it's brute-forced in `[0, 64)`: each guess
produces a different padding/glue and therefore a different forged token.
The **server itself is the oracle** — a wrong guess comes back "invalid
token", the correct one verifies and grants admin. No local crypto
knowledge of the secret is ever needed, just one legitimate guest token
and ≤64 submissions.

## Reproduction

The remote instance is a long-expired, time-boxed CTF box, so `server_mock.py`
is a faithful from-scratch reproduction of the described service (same
`H(secret||message)` construction, same guest token format, same
admin-grant condition) used to build and verify the attack end-to-end:

```
$ python3 server_mock.py &
[*] listening on 127.0.0.1:27391, secret len=16 (unknown to client)

$ python3 exploit.py 127.0.0.1 27391
guest msg: b'user=guest&admin=false'
guest tok: 014f558829074f4e6a72ce58c8851ae6963684f5b25e159000937831043f074d
secret_len=16 -> ADMIN ACCESS GRANTED: LYKNCTF{...}
```

The brute force correctly recovers `secret_len=16` (matching the mock's
`os.urandom(16)` secret) purely from the server's verdicts, then forges a
valid admin token with zero knowledge of the secret's actual bytes.

## Tools

- Python `hashlib`/`struct` for the guest-token oracle
- A from-scratch pure-Python SHA-256 compression core (`_compress`), so the
  hash state can be resumed mid-stream — this is the crux of the whole
  attack and isn't exposed by `hashlib` directly
- Raw `socket` (not `pwntools`) since this is a line-based text protocol
