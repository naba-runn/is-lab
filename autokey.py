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
    plaintext = ""
    keys = [key]

    for i, c in enumerate(cipher):
        p = A[(A.index(c) - keys[i]) % 26]
        plaintext += p
        keys.append(A.index(p))

    return plaintext


text = "the house is being sold tonight"

cipher = autokey_encrypt(text, 7)

print("Cipher :", cipher)
print("Plain  :", autokey_decrypt(cipher, 7))