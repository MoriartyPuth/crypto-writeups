# Shifting Away

| | |
|---|---|
| **Category** | Crypto |
| **Flag** | `bronco{Slowly_But_Surely_Shifting_Away_Into_The_PascalSnake_Strings_Of_Characters}` |

> I'm slowly shifting, shifting afar / Char after char, char after char /
> I'm slowly shifting (shifting afar) … Underscores against the stream /
> Braces against the stream. *(Source Material: Mr. Probz, "Waves", 2013)*

## Challenge

A single ciphertext line:

```
bqmkyj{Ldfmam_Nfd_Abxjpb_Thhdqeia_Snqn_Vzey_Bok_TdudakQkwfy_Kkhxbte_Yo_Jnfvdeueqq}
```

## Reasoning

The song parody ("shifting, shifting afar / char after char") describes a **progressive
Caesar shift** — a Caesar whose shift *grows* with position instead of staying constant.

The one subtlety that makes it resolve cleanly: the running index advances on **every**
character, including `{`, `_`, and `}`. Those symbols aren't themselves shifted, but they
still consume a position, so the letters after them line up correctly. To decrypt, subtract
the running index from each letter (mod 26, per case):

```
plain[i] = cipher[i] - i   (letters only; index counts all chars)
```

Trying it as "counter over all positions, direction = decrypt" is the only variant that
yields readable text.

## PoC / Reproduction

```
$ python solve.py
bronco{Slowly_But_Surely_Shifting_Away_Into_The_PascalSnake_Strings_Of_Characters}
```

`solve.py` is included — no arguments needed.

## Tools

- Python 3 (stdlib only).

## Key Takeaway

When a Caesar variant references "char after char" / increasing motion, try a **position-
dependent shift** and remember to decide whether non-alphabetic separators consume the
counter — here they do, which is what aligns the plaintext.
