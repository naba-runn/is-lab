from Crypto.Util.number import getPrime


def _prime_3_mod_4(bits):
    """p, q must be = 3 (mod 4) so decryption can extract square roots directly."""
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            return p


def rabin_generate_keys(bits=1024):
    p = _prime_3_mod_4(bits // 2)
    q = _prime_3_mod_4(bits // 2)
    n = p * q     # public key

    return n, (p, q)   # (public key, private key)


def rabin_encrypt(n, plaintext):
    return ",".join(str(pow(ord(ch), 2, n)) for ch in plaintext)


def rabin_decrypt(n, p, q, ciphertext, alphabet_size=256):
    plaintext = ""

    for part in ciphertext.split(","):
        c = int(part)

        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)

        yp = pow(p, -1, q)
        yq = pow(q, -1, p)

        r1 = (mp * q * yq + mq * p * yp) % n
        r2 = n - r1
        r3 = (mp * q * yq - mq * p * yp) % n
        r4 = n - r3

        # Rabin decryption yields 4 candidate roots; redundancy (root must be
        # a valid character code) picks out the real plaintext character.
        for root in (r1, r2, r3, r4):
            if 0 <= root < alphabet_size:
                plaintext += chr(root)
                break

    return plaintext


if __name__ == "__main__":
    n, (p, q) = rabin_generate_keys()

    message = "Patient record #4471"
    ciphertext = rabin_encrypt(n, message)
    decrypted = rabin_decrypt(n, p, q, ciphertext)

    print("Public key  n    :", n)
    print("Private key (p,q):", (p, q))
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)
