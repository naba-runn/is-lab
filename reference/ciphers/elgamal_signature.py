import hashlib
from Crypto.Util.number import getPrime, getRandomRange


def _hash_to_int(message, modulus):
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big") % modulus


def elgamal_generate_keys(bits=256):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 2)   # private key
    y = pow(g, x, p)               # public key

    return p, g, y, x


def elgamal_sign(message, p, g, x):
    while True:
        k = getRandomRange(2, p - 2)
        if pow(k, 1, p - 1) != 0 and _egcd(k, p - 1) == 1:
            break

    h = _hash_to_int(message, p - 1)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)

    return r, s


def elgamal_verify(message, r, s, p, g, y):
    if not (0 < r < p):
        return False

    h = _hash_to_int(message, p - 1)

    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)

    return v1 == v2


def _egcd(a, b):
    while b:
        a, b = b, a % b
    return a


if __name__ == "__main__":
    p, g, y, x = elgamal_generate_keys()
    message = "Alice"

    r, s = elgamal_sign(message, p, g, x)
    print("Message   :", message)
    print("Signature :", (r, s))
    print("Verified  :", elgamal_verify(message, r, s, p, g, y))

    print("Tampered  :", elgamal_verify("Mallory", r, s, p, g, y))
