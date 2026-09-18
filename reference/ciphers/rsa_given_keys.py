# For when a question GIVES you raw RSA numbers directly (e.g. "public key
# (n, e) where n = 323, e = 5" and "private key d = 173") instead of asking
# you to generate a keypair. Encrypts per-character so it also works with
# tiny textbook moduli that couldn't hold a whole message as one integer.

def rsa_encrypt(n, e, plaintext):
    return ",".join(str(pow(ord(ch), e, n)) for ch in plaintext)


def rsa_decrypt(n, d, ciphertext):
    return "".join(chr(pow(int(c), d, n)) for c in ciphertext.split(","))


if __name__ == "__main__":
    n, e, d = 323, 5, 173     # given public key (n, e) and private exponent d
    message = "Cryptographic Protocols"

    ciphertext = rsa_encrypt(n, e, message)
    decrypted = rsa_decrypt(n, d, ciphertext)

    print("Message   :", message)
    print("Ciphertext:", ciphertext)
    print("Decrypted :", decrypted)
