# Threshold (n-of-n) Paillier decryption: the private key is split between
# several trustees, and a ciphertext can only be decrypted when ALL of them
# take part. Used for "decrypt only the final aggregate" (e-voting tally,
# secure sum): each trustee decrypts nothing on its own.
#
#   decryption exponent  d = lam * mu        (c^d mod n^2 = 1 + m*n)
#   split it             d = s1 + s2 + ... + sk   (mod n*lam)
#   trustee i            partial_i = c^si mod n^2
#   combine              product of partials = c^d  ->  m = (c^d - 1) // n
#
# Any single share (or k-1 of them) is just a random number and reveals
# nothing. All values are ints.

import math
from Crypto.Util.number import getPrime, getRandomRange


# ---- from ciphers/paillier.py (verbatim) ----

def paillier_generate_keys(bits=1024):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p != q and math.gcd(p * q, (p - 1) * (q - 1)) == 1:
            break

    n = p * q
    g = n + 1
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)       # lcm(p-1, q-1)
    mu = pow((pow(g, lam, n * n) - 1) // n, -1, n)

    return n, g, lam, mu


def paillier_encrypt(n, g, message):
    n2 = n * n

    while True:
        r = getRandomRange(1, n)
        if math.gcd(r, n) == 1:
            break

    return (pow(g, message, n2) * pow(r, n, n2)) % n2


def paillier_add(n, c1, c2):
    return (c1 * c2) % (n * n)


# ---------- the threshold part ----------

def threshold_split_key(n, lam, mu, parties):
    """Split the private key into `parties` additive shares (one per trustee)."""
    modulus = n * lam
    d = (lam * mu) % modulus

    shares = [getRandomRange(0, modulus) for _ in range(parties - 1)]
    shares.append((d - sum(shares)) % modulus)

    return shares


def threshold_partial_decrypt(n, ciphertext, share):
    """What ONE trustee computes with its own share."""
    return pow(ciphertext, share, n * n)


def threshold_combine(n, partials):
    """Multiply every trustee's partial result -> the plaintext."""
    product = 1
    for partial in partials:
        product = (product * partial) % (n * n)

    return ((product - 1) // n) % n


if __name__ == "__main__":
    n, g, lam, mu = paillier_generate_keys(512)
    shares = threshold_split_key(n, lam, mu, 3)

    votes = [1, 0, 1, 1, 0, 1]
    total = paillier_encrypt(n, g, 0)
    for v in votes:
        total = paillier_add(n, total, paillier_encrypt(n, g, v))

    partials = [threshold_partial_decrypt(n, total, s) for s in shares]
    print("votes            :", votes)
    print("trustee shares   :", [str(s)[:12] + "..." for s in shares])
    print("all 3 trustees   :", threshold_combine(n, partials))
    print("only 2 trustees  :", str(threshold_combine(n, partials[:2]))[:20] + "...  (garbage)")
    assert threshold_combine(n, partials) == sum(votes)
