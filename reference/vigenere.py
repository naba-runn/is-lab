import string

A = string.ascii_lowercase


def vigenere_encrypt(text, key):
    text = ''.join(c for c in text.lower() if c.isalpha())
    key = ''.join(c for c in key.lower() if c.isalpha())

    return ''.join(
        A[(A.index(c) + A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(text)
    )


def vigenere_decrypt(cipher, key):
    cipher = ''.join(c for c in cipher.lower() if c.isalpha())
    key = ''.join(c for c in key.lower() if c.isalpha())

    return ''.join(
        A[(A.index(c) - A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(cipher)
    )


if __name__ == "__main__":
    text = "the house is being sold tonight"
    key = "dollars"

    cipher = vigenere_encrypt(text, key)

    print("Cipher :", cipher)
    print("Plain  :", vigenere_decrypt(cipher, key))
