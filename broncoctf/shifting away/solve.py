#!/usr/bin/env python3
"""
Bronco CTF - Shifting Away
Progressive Caesar shift: char at index i is shifted by i, and the running
index advances on EVERY character (letters, braces, underscores alike).
Decrypt by subtracting the running index from each letter.
"""

CT = "bqmkyj{Ldfmam_Nfd_Abxjpb_Thhdqeia_Snqn_Vzey_Bok_TdudakQkwfy_Kkhxbte_Yo_Jnfvdeueqq}"


def shift_char(c, s):
    if c.isupper():
        return chr((ord(c) - 65 - s) % 26 + 65)
    if c.islower():
        return chr((ord(c) - 97 - s) % 26 + 97)
    return c


def decrypt(ct, count_all=True, direction=-1):
    out, idx = [], 0
    for c in ct:
        if c.isalpha():
            out.append(shift_char(c, idx * direction))
            if not count_all:
                idx += 1
        else:
            out.append(c)
        if count_all:
            idx += 1
    return "".join(out)


if __name__ == "__main__":
    # winning combo: counter over ALL positions, subtract the index
    print(decrypt(CT, count_all=True, direction=-1))
    # -> bronco{Slowly_But_Surely_Shifting_Away_Into_The_PascalSnake_Strings_Of_Characters}
