#!/usr/bin/env python3
"""
Bronco CTF - Emojibius
5 emojis (indices 0-4) key a 5x5 Polybius grid written on the face.
Each emoji PAIR is a (row, col) coordinate.
"""

emap = {"🍎": 0, "🦊": 1, "🍐": 2, "🐶": 3, "🎈": 4}

# 5x5 grid read off the face in the hint image
grid = [
    ["b", "r", "o", "n", "c"],
    ["{", "e", "m", "0", "j"],
    ["1", "s", "_", "g", "3"],
    ["}", "a", "d", "f", "h"],
    ["i", "k", "l", "p", "q"],
]

# intercepted_signals.txt
signals = (
    "🍎🍎 🍎🦊 🍎🍐 🍎🐶 🍎🎈 🍎🍐 🦊🍎 🦊🦊 🦊🍐 🦊🐶 🦊🎈 🍐🍎 "
    "🍐🦊 🍐🍐 🍎🦊 🍐🍐 🍎🎈 🍎🦊 🍐🍎 🍎🐶 🍐🐶 🍐🎈 🐶🍎"
).split()


def solve():
    out = ""
    for pair in signals:
        a, b = list(pair)
        out += grid[emap[a]][emap[b]]
    return out


if __name__ == "__main__":
    print(solve())  # -> bronco{em0j1s_r_cr1ng3}
