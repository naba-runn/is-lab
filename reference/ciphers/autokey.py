import string

A = string.ascii_lowercase


def autokey_encrypt(text, key):
    text = ''.join(c for c in text.lower() if c.isalpha())

    keys = [key] + [A.index(c) for c in text[:-1]]

    return ''.join(
        A[(A.index(c) + keys[i]) % 26]
        for i, c in enumerate(text)
    )


def autokey_decrypt(cipher, key):
    cipher = ''.join(c for c in cipher.lower() if c.isalpha())

    plaintext = ""
    keys = [key]

    for i, c in enumerate(cipher):
        p = A[(A.index(c) - keys[i]) % 26]
        plaintext += p
        keys.append(A.index(p))

    return plaintext


if __name__ == "__main__":
    text = "the house is being sold tonight"
    key = 7

    cipher = autokey_encrypt(text, key)

    print("Cipher :", cipher)
    print("Plain  :", autokey_decrypt(cipher, key))
