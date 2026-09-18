import hashlib
from Crypto.Util.number import getPrime, getRandomRange, isPrime


def _hash_to_int(*parts, modulus):
    digest = hashlib.sha256("".join(str(p) for p in parts).encode()).digest()
    return int.from_bytes(digest, "big") % modulus


def schnorr_generate_domain_parameters(q_bits=64):
    """A safe prime p = 2q + 1 gives a subgroup of prime order q that g lives in."""
    while True:
        q = getPrime(q_bits)
        p = 2 * q + 1
        if isPrime(p):
            break

    while True:
        h = getRandomRange(2, p - 1)
        g = pow(h, 2, p)
        if g != 1:
            break

    return p, q, g


def schnorr_generate_keys(p, q, g):
    x = getRandomRange(2, q - 1)   # private key
    y = pow(g, x, p)               # public key

    return y, x


def schnorr_sign(message, p, q, g, x):
    k = getRandomRange(2, q - 1)
    r = pow(g, k, p)

    e = _hash_to_int(r, message, modulus=q)
    s = (k + x * e) % q

    return e, s


def schnorr_verify(message, e, s, p, q, g, y):
    r_check = (pow(g, s, p) * pow(y, -e, p)) % p
    e_check = _hash_to_int(r_check, message, modulus=q)

    return e_check == e


if __name__ == "__main__":
    p, q, g = schnorr_generate_domain_parameters()
    y, x = schnorr_generate_keys(p, q, g)

    message = "Alice"
    e, s = schnorr_sign(message, p, q, g, x)

    print("Message   :", message)
    print("Signature :", (e, s))
    print("Verified  :", schnorr_verify(message, e, s, p, q, g, y))

    print("Tampered  :", schnorr_verify("Mallory", e, s, p, q, g, y))
