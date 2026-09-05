from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

numbers = private_key.private_numbers()

n = numbers.public_numbers.n
e = numbers.public_numbers.e
d = numbers.private_numbers.d

message = b"Asymmetric Encryption"

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

decrypted = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Public Key  (n, e) =", (n, e))
print("Private Key (n, d) =", (n, d))
print("Ciphertext =", ciphertext.hex())
print("Decrypted  =", decrypted.decode())

#RSA's public key is: (n,e) 
#and the private key is: (n,d)