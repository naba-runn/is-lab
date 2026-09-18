import string

A = string.ascii_lowercase


def additive_encrypt(text, key):
    return ''.join(A[(A.index(c) + key) % 26]
                   for c in text.lower() if c.isalpha())


def additive_decrypt(text, key):
    return ''.join(A[(A.index(c) - key) % 26]
                   for c in text.lower() if c.isalpha())


def multiplicative_encrypt(text, key):
    return ''.join(A[(A.index(c) * key) % 26]
                   for c in text.lower() if c.isalpha())


def multiplicative_decrypt(text, key):
    inv = pow(key, -1, 26)
    return ''.join(A[(A.index(c) * inv) % 26]
                   for c in text.lower() if c.isalpha())


def affine_encrypt(text, a, b):
    return ''.join(A[(a * A.index(c) + b) % 26]
                   for c in text.lower() if c.isalpha())


def affine_decrypt(text, a, b):
    inv = pow(a, -1, 26)
    return ''.join(A[(inv * (A.index(c) - b)) % 26]
                   for c in text.lower() if c.isalpha())


if __name__ == "__main__":
    text = "I am learning information security"

    # a) Additive
    c1 = additive_encrypt(text, 20)
    print("Additive :", c1)
    print("Decrypt  :", additive_decrypt(c1, 20))

    # b) Multiplicative
    c2 = multiplicative_encrypt(text, 15)
    print("Multiplicative :", c2)
    print("Decrypt        :", multiplicative_decrypt(c2, 15))

    # c) Affine
    c3 = affine_encrypt(text, 15, 20)
    print("Affine :", c3)
    print("Decrypt:", affine_decrypt(c3, 15, 20))
