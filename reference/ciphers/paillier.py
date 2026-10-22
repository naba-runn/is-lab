# Paillier: public-key encryption that is ADDITIVELY homomorphic -- you can add
# numbers while they are still encrypted.
#
#   Enc(a) * Enc(b)  mod n^2  =  Enc(a + b)     paillier_add
#   Enc(a) * g^k     mod n^2  =  Enc(a + k)     paillier_add_plain
#   Enc(a) / Enc(b)  mod n^2  =  Enc(a - b)     paillier_subtract
#   Enc(a) ^ k       mod n^2  =  Enc(a * k)     paillier_multiply_plain
#
# Everything here is an int: n, g, lam, mu, the messages AND the ciphertexts
# (a ciphertext is not a hex string). Messages must satisfy 0 <= m < n; a
# negative result comes back as n - |result|.
#
# Public key (n, g); private key (lam, mu). g = n + 1 is the standard choice.

import math
from Crypto.Util.number import getPrime, getRandomRange


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


def paillier_decrypt(n, lam, mu, ciphertext):
    l = (pow(ciphertext, lam, n * n) - 1) // n

    return (l * mu) % n


def paillier_add(n, c1, c2):
    return (c1 * c2) % (n * n)


def paillier_add_plain(n, g, ciphertext, k):
    return (ciphertext * pow(g, k % n, n * n)) % (n * n)


def paillier_subtract(n, c1, c2):
    return (c1 * pow(c2, -1, n * n)) % (n * n)


def paillier_multiply_plain(n, ciphertext, k):
    return pow(ciphertext, k, n * n)


if __name__ == "__main__":
    n, g, lam, mu = paillier_generate_keys()
    print("Public key  (n, g) : n has", n.bit_length(), "bits, g = n + 1")
    print("Private key (lam, mu)")

    a, b = 15, 25
    ciphertext_a = paillier_encrypt(n, g, a)
    ciphertext_b = paillier_encrypt(n, g, b)
    print("\nCiphertext of", a, ":", ciphertext_a)
    print("Ciphertext of", b, ":", ciphertext_b)

    # the same message encrypts differently every time (random r), yet both decrypt
    print("\nEncrypting", a, "again gives a different ciphertext:", paillier_encrypt(n, g, a) != ciphertext_a)

    # add WITHOUT decrypting
    ciphertext_sum = paillier_add(n, ciphertext_a, ciphertext_b)
    print("\nEncrypted sum (a + b):", ciphertext_sum)

    decrypted_sum = paillier_decrypt(n, lam, mu, ciphertext_sum)
    print("Decrypted sum        :", decrypted_sum)
    print("matches", a, "+", b, "=", a + b, ":", decrypted_sum == a + b)

    # the other homomorphic operations
    print("\nEnc(a) + 100 -> ", paillier_decrypt(n, lam, mu, paillier_add_plain(n, g, ciphertext_a, 100)))
    print("Enc(b) - Enc(a) ->", paillier_decrypt(n, lam, mu, paillier_subtract(n, ciphertext_b, ciphertext_a)))
    print("Enc(a) * 4 ->      ", paillier_decrypt(n, lam, mu, paillier_multiply_plain(n, ciphertext_a, 4)))

    # Paillier adds but cannot multiply two ciphertexts: Enc(a) * Enc(b) is the SUM.
    # (Enc(a) ^ Enc(b) would not decrypt to a*b -- that needs a fully homomorphic scheme.)
