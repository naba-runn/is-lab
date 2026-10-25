# DSA (Diffie-Hellman domain) digital signature -- SAME interface as every other *_signature.py:
#
#   dh_sign(message, p, q, g, x)              -> signature as a STRING "r,s"
#   dh_verify(message, signature, p, q, g, y)  -> True / False
#
# The signature may be that string or the two numbers / a tuple read back from a
# file -- verify converts it.

# Diffie-Hellman is a key-exchange protocol, not a signature scheme -- it has
# no "sign" operation. The standard way to get digital signatures out of the
# same discrete-log / (p, q, g) domain parameters DH uses is DSA (the Digital
# Signature Algorithm), so that's what this file implements.

import hashlib
from Crypto.Util.number import getPrime, getRandomRange, isPrime


def _hash_to_int(message, modulus):
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big") % modulus


def dh_generate_domain_parameters(q_bits=64, p_bits=256):
    while True:
        q = getPrime(q_bits)

        for _ in range(200):
            k = getRandomRange(2 ** (p_bits - q_bits - 1), 2 ** (p_bits - q_bits))
            p = k * q + 1
            if isPrime(p):
                break
        else:
            continue
        break

    while True:
        h = getRandomRange(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g != 1:
            break

    return p, q, g


def dh_generate_keys(p, q, g):
    x = getRandomRange(2, q - 1)   # private key
    y = pow(g, x, p)               # public key

    return y, x


def dh_sign(message, p, q, g, x):
    h = _hash_to_int(message, q)

    while True:
        k = getRandomRange(2, q - 1)
        r = pow(g, k, p) % q
        if r == 0:
            continue

        k_inv = pow(k, -1, q)
        s = (k_inv * (h + x * r)) % q
        if s != 0:
            break

    return str(r) + "," + str(s)


def dh_verify(message, signature, p, q, g, y):
    r, s = _split_signature(signature)
    if not (0 < r < q and 0 < s < q):
        return False

    h = _hash_to_int(message, q)
    w = pow(s, -1, q)

    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    return v == r


def _split_signature(signature):
    """A signature is the string "a,b"; numbers or a tuple (e.g. read from a file) work too."""
    if isinstance(signature, str):
        first, second = signature.split(",")
        return int(first), int(second)
    return int(signature[0]), int(signature[1])


if __name__ == "__main__":
    p, q, g = dh_generate_domain_parameters()
    y, x = dh_generate_keys(p, q, g)

    message = "Alice"
    signature = dh_sign(message, p, q, g, x)

    print("Message   :", message)
    print("Signature :", signature)
    print("Verified  :", dh_verify(message, signature, p, q, g, y))
    print("Tampered  :", dh_verify("Mallory", signature, p, q, g, y))
