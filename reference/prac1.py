import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

A = string.ascii_lowercase


def vigenere_encrypt(text, key):
    text = ''.join(c for c in text.lower() if c.isalpha())

    return ''.join(
        A[(A.index(c) + A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(text)
    )


def vigenere_decrypt(cipher, key):
    return ''.join(
        A[(A.index(c) - A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(cipher)
    )


def aes_generate_key():
    return "1234567890123456"


def aes_encrypt(key, plaintext):
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes_decrypt(key, ciphertext):
    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


def rsa_generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    numbers = private_key.private_numbers()

    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d

    return private_key, public_key, n, e, d


def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()


def rsa_decrypt(private_key, ciphertext):
    decrypted = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted.decode()


text = "Hi manipal how are you?"
key1 = "dollars"

# 1. Vigenere encrypt the text
c1 = vigenere_encrypt(text, key1)

# 2. AES encrypt the vigenere ciphertext
key2 = aes_generate_key()
c2 = aes_encrypt(key2, c1)

# 3. RSA encrypt the AES key
private_key, public_key, n, e, d = rsa_generate_keys()
c3 = rsa_encrypt(public_key, key2)

# ---- decryption (reverse order) ----

# 3'. RSA decrypt to recover the AES key
p3 = rsa_decrypt(private_key, c3)

# 2'. AES decrypt to recover the vigenere ciphertext
p2 = aes_decrypt(p3, c2)

# 1'. Vigenere decrypt to recover the original text
p1 = vigenere_decrypt(p2, key1)

print("Original text          :", text)
print("Vigenere ciphertext c1 :", c1)
print("AES ciphertext c2      :", c2)
print("RSA-encrypted key c3   :", c3)
print("Recovered AES key      :", p3)
print("Recovered vigenere ct  :", p2)
print("Final decrypted text   :", p1)
