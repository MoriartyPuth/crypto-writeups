# Emojibius

| | |
|---|---|
| **Category** | Crypto |
| **Flag** | `bronco{em0j1s_r_cr1ng3}` |

> Our intelligence agency has intercepted a strange transmission. It looks like Gen-Z
> developed a new language. We found a cryptic image of an elderly person on a nearby
> server?? Can you recover the secret message?
>
> Hint: Sometimes you can tell what's written all over someone's face.

## Challenge

`intercepted_signals.txt` — a stream of emoji **pairs**:

```
🍎🍎 🍎🦊 🍎🍐 🍎🐶 🍎🎈 🍎🍐 🦊🍎 🦊🦊 🦊🍐 🦊🐶 🦊🎈 🍐🍎 🍐🦊 🍐🍐 🍎🦊 🍐🍐 🍎🎈 🍎🦊 🍐🍎 🍎🐶 🍐🐶 🍐🎈 🐶🍎
```

Plus a hint image: an elderly person with 5 emojis across the forehead and a faint 5×5
grid of characters written on the face.

## Reasoning

This is a **Polybius square** keyed by emojis. The 5 forehead emojis `🍎🦊🍐🐶🎈` are the
coordinate symbols (indices 0–4). Each emoji **pair** is a `(row, col)` into the 5×5 grid
read off the face ("written all over someone's face"):

```
      🍎   🦊   🍐   🐶   🎈
🍎    b    r    o    n    c
🦊    {    e    m    0    j
🍐    1    s    _    g    3
🐶    }    a    d    f    h
🎈    i    k    l    p    q
```

First emoji = row, second = column, look up the character.

## PoC / Reproduction

```
$ python solve.py
bronco{em0j1s_r_cr1ng3}
```

`solve.py` and `intercepted_signals.txt` are included.

## Tools

- Python 3 (stdlib only).

## Key Takeaway

A "new emoji language" using a fixed small symbol set (here 5) in **pairs** is a classic
Polybius/coordinate substitution in disguise — recover the grid (often hidden in an image)
and decode `(row, col)` pairs. Flag reads "emojis r cringe".
