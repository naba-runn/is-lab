# ElGamal homomorphic encryption (lab 7).
#
# Standard ElGamal is MULTIPLICATIVE:
#   Enc(a) = (g^k1, a*h^k1),  Enc(b) = (g^k2, b*h^k2)
#   multiply component-wise  -> (g^(k1+k2), a*b*h^(k1+k2)) = Enc(a * b)
#   multiply c2 by k         -> Enc(k * a)
#   raise both parts to k    -> Enc(a^k)
# It cannot ADD.
#
# Exponential ("additive") ElGamal encrypts g^m instead of m:
#   Enc(g^a) * Enc(g^b) = Enc(g^(a+b))   -> a SUM
# Decryption gives g^sum, and sum is found by trying 0, 1, 2, ... (a discrete
# log), so it only works for small totals.
#
# Messages for the multiplicative version must be 1 .. p-1 (0 has no inverse).
# Ciphertexts are (c1, c2) tuples of ints.

from Crypto.Util.number import getPrime, getRandomRange


def elgamal_he_generate_keys(bits=512):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 1)   # private key
    h = pow(g, x, p)               # public key

    return p, g, h, x


def elgamal_he_encrypt(p, g, h, m):
    k = getRandomRange(2, p - 1)

    return pow(g, k, p), (m * pow(h, k, p)) % p


def elgamal_he_decrypt(p, x, ciphertext):
    c1, c2 = ciphertext
    s = pow(c1, x, p)

    return (c2 * pow(s, -1, p)) % p


def elgamal_he_multiply(p, ct1, ct2):
    return (ct1[0] * ct2[0]) % p, (ct1[1] * ct2[1]) % p


def elgamal_he_multiply_plain(p, ciphertext, k):
    return ciphertext[0], (ciphertext[1] * k) % p


def elgamal_he_power(p, ciphertext, k):
    return pow(ciphertext[0], k, p), pow(ciphertext[1], k, p)


def elgamal_exp_encrypt(p, g, h, m):
    return elgamal_he_encrypt(p, g, h, pow(g, m, p))


def elgamal_exp_decrypt(p, g, x, ciphertext, limit=1000000):
    target = elgamal_he_decrypt(p, x, ciphertext)      # g^m
    value = 1
    for m in range(limit):
        if value == target:
            return m
        value = (value * g) % p
    raise ValueError("sum is larger than the search limit")


if __name__ == "__main__":
    p, g, h, x = elgamal_he_generate_keys()
    a, b, k = 7, 3, 5

    ca, cb = elgamal_he_encrypt(p, g, h, a), elgamal_he_encrypt(p, g, h, b)
    print("Enc(7) * Enc(3) ->", elgamal_he_decrypt(p, x, elgamal_he_multiply(p, ca, cb)))
    print("Enc(7) * 5      ->", elgamal_he_decrypt(p, x, elgamal_he_multiply_plain(p, ca, k)))
    print("Enc(7) ^ 5      ->", elgamal_he_decrypt(p, x, elgamal_he_power(p, ca, k)))

    ea, eb = elgamal_exp_encrypt(p, g, h, a), elgamal_exp_encrypt(p, g, h, b)
    print("exponential: Enc(g^7) * Enc(g^3) ->", elgamal_exp_decrypt(p, g, x, elgamal_he_multiply(p, ea, eb)))

    assert elgamal_he_decrypt(p, x, elgamal_he_multiply(p, ca, cb)) == 21
    assert elgamal_he_decrypt(p, x, elgamal_he_multiply_plain(p, ca, k)) == 35
    assert elgamal_he_decrypt(p, x, elgamal_he_power(p, ca, k)) == 7 ** 5
    assert elgamal_exp_decrypt(p, g, x, elgamal_he_multiply(p, ea, eb)) == 10
