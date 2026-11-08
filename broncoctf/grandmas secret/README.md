# Grandma's Secret

| | |
|---|---|
| **Category** | Crypto |
| **Flag / Secret** | `bronco{JELLYDONUT}` (Grandma's WiFi password) |

> Grandma wants to protect her WiFi password. Can you find out what it is before Grandpa
> does?

## Challenge

A handwritten letter (`Letter.jpeg`) from Grandma. It contains everything needed:

- a 6×6 **Polybius square** with rows/cols labelled `A D F G V X`,
- the transposition key hidden in prose — **SUGAR** ("alphabetically sorted SUGAR filled
  treats"),
- and the ciphertext as the odd all-caps words: `GVXX FVXV AFXF XVGA DAFF`.

## Reasoning

This is the **ADFGVX cipher** (fractionating substitution + columnar transposition).
Decrypt by undoing the transposition first:

1. `SUGAR` in alphabetical order is `A-G-R-S-U`, so the five ciphertext groups are the
   columns read in that order. Place them back into the physical `S U G A R` columns of a
   4×5 grid.
2. Read the grid **row by row** to recover the digraph stream:
   `XD FG AV AV VF GF XX XA FV XF`.
3. Look up each digraph in the square (first letter = row, second = column):

```
XD FG AV AV VF GF XX XA FV XF  ->  J  E  L  L  Y  D  O  N  U  T
```

## PoC / Reproduction

```
$ python solve.py
JELLYDONUT
```

`solve.py` and `Letter.jpeg` are included.

## Tools

- Python 3 (stdlib only).

## Key Takeaway

ADFGVX gives itself away by its 6-symbol `ADFGVX` alphabet. The only fiddly step is the
columnar transposition inverse — sort the key letters, map ciphertext groups back to their
physical columns, then read rows. The recovered WiFi password is a SUGAR-filled treat:
`JELLYDONUT`.
