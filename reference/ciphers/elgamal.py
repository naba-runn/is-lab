from Crypto.Util.number import getPrime, getRandomRange


def elgamal_generate_keys(bits=256):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 1)   # private key
    h = pow(g, x, p)               # public key component

    return p, g, h, x


def elgamal_encrypt(p, g, h, plaintext):
    parts = []

    for ch in plaintext:
        m = ord(ch)
        k = getRandomRange(2, p - 1)

        c1 = pow(g, k, p)
        c2 = (m * pow(h, k, p)) % p

        parts.append(f"{c1}:{c2}")

    return ",".join(parts)


def elgamal_decrypt(p, x, ciphertext):
    plaintext = ""

    for part in ciphertext.split(","):
        c1, c2 = map(int, part.split(":"))

        s = pow(c1, x, p)
        m = (c2 * pow(s, -1, p)) % p

        plaintext += chr(m)

    return plaintext


if __name__ == "__main__":
    p, g, h, x = elgamal_generate_keys()

    message = "Confidential Data"

    ciphertext = elgamal_encrypt(p, g, h, message)
    decrypted = elgamal_decrypt(p, x, ciphertext)

    print("Public Key  (p, g, h) =", (p, g, h))
    print("Private Key x         =", x)
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)
