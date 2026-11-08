#!/usr/bin/env python3
"""
Bronco CTF - Consistently Static Pseudo Random Number Generator

1. Each oracle line leaks (guess%12, guess%7, guess%5). Since lcm(12,7,5)=420>256,
   CRT recovers the exact PRNG output byte a_i for every line.
2. next() does a = sum(state)%256 then overwrites one slot with a, so
       val_i = flag[schedule[i]] = (2*a_i - a_{i+1}) mod 256   (first pass over schedule)
3. schedule is identity, rotated by an unknown shift and optionally reversed.
   Brute the (shift, reverse) and read the printable bronco{...}. N=34 (trailing \n).

Place the challenge transcript in results.txt next to this script.
"""
import os
import re

months = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]
days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
areas = ["Asia", "Africa", "the Americas", "Europe", "Australia"]

HERE = os.path.dirname(os.path.abspath(__file__))


def load_outputs(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    a_list = []
    for mo, dy, ar in re.findall(r"born in (\w+)\.\.\. on a (\w+), in (.+)", text):
        mi, di, ai = months.index(mo), days.index(dy), areas.index(ar.strip())
        for g in range(256):
            if g % 12 == mi and g % 7 == di and g % 5 == ai:
                a_list.append(g)
                break
    return a_list


def solve(a_list):
    N = 34  # flag length incl. trailing newline
    # val_i = flag[schedule[i]] = (2*a_i - a_{i+1}) mod 256 ; first N cover every slot once
    vals = [(2 * a_list[i] - a_list[i + 1]) % 256 for i in range(N)]

    def printable(b):
        return 32 <= b < 127

    # schedule = identity rotated by `shift`, optionally reversed
    for reverse in (False, True):
        for shift in range(N):
            sched = list(range(N))
            sched = sched[shift:] + sched[:shift]
            if reverse:
                sched = sched[::-1]
            flag = [0] * N
            for i in range(N):
                flag[sched[i]] = vals[i]
            s = bytes(b & 0xFF for b in flag)
            if s.startswith(b"bronco{"):
                body = s.rstrip(b"\n")
                if body.endswith(b"}") and all(printable(x) for x in body):
                    return body.decode()
    return None


if __name__ == "__main__":
    path = os.path.join(HERE, "results.txt")
    if not os.path.exists(path):
        print("Put the oracle transcript in results.txt next to this script.")
        raise SystemExit(1)
    a_list = load_outputs(path)
    print("recovered", len(a_list), "PRNG output bytes")
    print("flag:", solve(a_list))  # -> bronco{crypt0_1n5ecur3_4_c3rt4in}
