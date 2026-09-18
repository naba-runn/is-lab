from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


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


if __name__ == "__main__":
    private_key, public_key, n, e, d = rsa_generate_keys()

    message = "Asymmetric Encryption"

    ciphertext = rsa_encrypt(public_key, message)
    decrypted = rsa_decrypt(private_key, ciphertext)

    print("Public Key  (n, e) =", (n, e))
    print("Private Key (n, d) =", (n, d))
    print("Ciphertext =", ciphertext)
    print("Decrypted  =", decrypted)

#RSA's public key is: (n,e)
#and the private key is: (n,d)
