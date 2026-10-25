# Textbook RSA on whole integers, to show its MULTIPLICATIVE homomorphism:
#
#   Enc(a) * Enc(b)  mod n  =  (a^e)(b^e) = (a*b)^e  =  Enc(a * b)
#
# This only works because textbook RSA has NO padding. ciphers/rsa.py uses OAEP
# padding on purpose, which destroys this property (and is why OAEP is safe).
# Unpadded RSA is deterministic and malleable -- fine for this lab, never for
# real data.
#
# Everything is an int. Keep a, b and a*b below n or the product wraps around.

import math
from Crypto.Util.number import getPrime


def rsa_he_generate_keys(bits=1024):
    e = 65537

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1:
            break

    d = pow(e, -1, phi)

    return p * q, e, d


def rsa_he_encrypt(n, e, message):
    return pow(message, e, n)


def rsa_he_decrypt(n, d, ciphertext):
    return pow(ciphertext, d, n)


def rsa_he_multiply(n, c1, c2):
    return (c1 * c2) % n


def rsa_he_multiply_plain(n, e, ciphertext, k):
    """Enc(m) * k^e = Enc(k * m)."""
    return (ciphertext * pow(k, e, n)) % n


def rsa_he_power(n, ciphertext, k):
    """Enc(m)^k = (m^e)^k = Enc(m^k)."""
    return pow(ciphertext, k, n)


if __name__ == "__main__":
    n, e, d = rsa_he_generate_keys()
    print("Public key  (n, e): n has", n.bit_length(), "bits, e =", e)

    a, b = 7, 3
    ciphertext_a = rsa_he_encrypt(n, e, a)
    ciphertext_b = rsa_he_encrypt(n, e, b)
    print("\nCiphertext of", a, ":", ciphertext_a)
    print("Ciphertext of", b, ":", ciphertext_b)

    ciphertext_product = rsa_he_multiply(n, ciphertext_a, ciphertext_b)
    print("\nEncrypted product (a * b):", ciphertext_product)

    decrypted_product = rsa_he_decrypt(n, d, ciphertext_product)
    print("Decrypted product        :", decrypted_product)
    print("matches", a, "*", b, "=", a * b, ":", decrypted_product == a * b)

    print("Enc(7) * 5^e ->", rsa_he_decrypt(n, d, rsa_he_multiply_plain(n, e, ciphertext_a, 5)))
    print("Enc(7) ^ 5   ->", rsa_he_decrypt(n, d, rsa_he_power(n, ciphertext_a, 5)))

    # RSA cannot ADD ciphertexts: Enc(a) + Enc(b) does not decrypt to a + b.
    decrypted_wrong_sum = rsa_he_decrypt(n, d, (ciphertext_a + ciphertext_b) % n)
    print("\nadding the ciphertexts gives the right sum?", decrypted_wrong_sum == a + b,
          "(use ciphers/paillier.py to add)")
