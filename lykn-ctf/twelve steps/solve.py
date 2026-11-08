import socket
import re
import math


def solve_lcg(outs):
    # Step 1: Recover modulus m
    ts = [outs[i+1] - outs[i] for i in range(len(outs)-1)]
    vals = []
    for i in range(1, len(ts)-1):
        v = ts[i+1] * ts[i-1] - ts[i] * ts[i]
        vals.append(abs(v))

    m = vals[0]
    for v in vals[1:]:
        m = math.gcd(m, v)
    m = abs(m)

    # Step 2: Recover a and c
    a = (ts[1] * pow(ts[0], -1, m)) % m
    c = (outs[1] - a * outs[0]) % m

    # Verify against all given outputs
    for i in range(len(outs)-1):
        assert (a * outs[i] + c) % m == outs[i+1]

    # Step 3: Predict next value
    return (a * outs[-1] + c) % m


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("51.79.140.18", 19557))

    data = b""
    while b"out[12]" not in data:
        data += s.recv(4096)
    text = data.decode()

    nums = [int(x) for x in re.findall(r'out\[\d+\] = (\d+)', text)]
    print("Received numbers:", nums)

    pred = solve_lcg(nums)
    print("Predicted out[12]:", pred)

    s.sendall(f"{pred}\n".encode())
    resp = s.recv(4096).decode()
    print("Response:", resp)
    s.close()


if __name__ == "__main__":
    main()
