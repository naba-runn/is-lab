# Breaking RSA that was set up badly. Each attack ends with the FIX to state
# in an answer.
#
#   1. p and q too close together   -> fermat_factor
#   2. same n, two different e      -> common_modulus_attack
#   3. e = 3, no padding, short m   -> low_exponent_attack
#
# Notation: n = p*q, public key (n, e), private exponent d, ciphertext c.

import math


# ---------- 1. Weak primes (p close to q) ----------
# n is then almost a perfect square, so the search below ends after very few
# steps. FIX: generate p and q independently, each >= 1024 bits, and reject a
# pair that is close together.

def fermat_factor(n):
    a = math.isqrt(n) + 1
    b_squared = a * a - n
    while math.isqrt(b_squared) ** 2 != b_squared:
        a += 1
        b_squared = a * a - n
    b = math.isqrt(b_squared)

    return a - b, a + b            # p, q


def private_exponent_from_factors(e, p, q):
    """Once n is factored, the private key follows immediately."""
    return pow(e, -1, (p - 1) * (q - 1))


# ---------- 2. Common modulus ----------
# The same message was sent to two people who share n but have different
# (coprime) exponents e1, e2. Anyone holding both ciphertexts recovers it with
# NO private key. FIX: never share n between recipients.

def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def common_modulus_attack(c1, c2, e1, e2, n):
    g, a, b = _egcd(e1, e2)                    # a*e1 + b*e2 = g = 1
    if g != 1:
        raise ValueError("e1 and e2 must be coprime")

    part1 = pow(c1, a, n) if a >= 0 else pow(pow(c1, -1, n), -a, n)
    part2 = pow(c2, b, n) if b >= 0 else pow(pow(c2, -1, n), -b, n)

    return (part1 * part2) % n


# ---------- 3. Low exponent ----------
# If m**e < n the ciphertext c = m**e never wraps around n, so m is simply the
# integer e-th root of c. FIX: OAEP padding (ciphers/rsa.py uses it) and a
# standard exponent such as 65537.

def integer_root(x, k):
    """Largest integer r with r**k <= x."""
    low, high = 0, 1 << (x.bit_length() // k + 1)
    while low < high:
        middle = (low + high + 1) // 2
        if middle ** k <= x:
            low = middle
        else:
            high = middle - 1
    return low


def low_exponent_attack(c, e):
    root = integer_root(c, e)
    if root ** e != c:
        raise ValueError("c is not a perfect e-th power: m**e wrapped around n")
    return root


def number_to_text(m):
    return m.to_bytes((m.bit_length() + 7) // 8, "big").decode()


if __name__ == "__main__":
    # 1. weak primes
    p, q, e = 100000007, 100000037, 65537
    n = p * q
    ciphertext = pow(4242, e, n)

    found_p, found_q = fermat_factor(n)
    d = private_exponent_from_factors(e, found_p, found_q)
    print("1. Fermat recovers the plaintext:", pow(ciphertext, d, n) == 4242)

    # 2. common modulus
    message = 999
    c1, c2 = pow(message, 7, n), pow(message, 11, n)
    print("2. common modulus recovers it   :", common_modulus_attack(c1, c2, 7, 11, n) == message)

    # 3. low exponent, with a real text message
    big_n = 2 ** 2047 + 1                      # any modulus far larger than m**3
    c = pow(int.from_bytes(b"attack at dawn", "big"), 3, big_n)
    print("3. low exponent recovers        :", number_to_text(low_exponent_attack(c, 3)))
