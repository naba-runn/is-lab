from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getRandomRange
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import hashlib


# ---- from ciphers/aes.py (verbatim) ----

def aes_generate_key():
    return "1234567890123456"


def aes_encrypt(key, plaintext, iv=None):
    key_bytes = key.encode() if isinstance(key, str) else key
    iv = iv or get_random_bytes(AES.block_size)

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes_decrypt(key, ciphertext):
    key_bytes = key.encode() if isinstance(key, str) else key

    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


# ---- from ciphers/rsa.py (verbatim) ----

def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


# ---- from ciphers/elgamal.py (verbatim) ----

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


# ---- from ciphers/hashing.py (verbatim) ----

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


if __name__ == "__main__":
    # 1. Create a file and add content to it
    original_file = "patient_record.txt"
    with open(original_file, "w") as f:
        f.write("Patient: John Doe\nDiagnosis: Hypertension\nPrescription: Amlodipine 5mg")
    print(f"Created '{original_file}'")

    with open(original_file, "r") as f:
        content = f.read()

    # 2. Encrypt the file content using AES, store the encrypted msg in another file
    aes_key = aes_generate_key()
    encrypted_content = aes_encrypt(aes_key, content)

    encrypted_file = "patient_record.enc"
    with open(encrypted_file, "w") as f:
        f.write(encrypted_content)
    print(f"Encrypted content written to '{encrypted_file}'")

    # 3. Using RSA, encrypt the AES key and store in another file
    private_key, public_key, n, e, d = rsa_generate_keys()
    encrypted_key = rsa_encrypt(public_key, aes_key)

    key_file = "aes_key.enc"
    with open(key_file, "w") as f:
        f.write(encrypted_key)
    print(f"RSA-encrypted AES key written to '{key_file}'")

    # 4. An authorization code is given -- encrypt it using ElGamal under given parameters
    p, g, x = 7919, 2, 2999            # <- given parameters (private key x)
    h = pow(g, x, p)                   # public key component, from the given parameters
    auth_code = "AUTH-4471"
    elgamal_ciphertext = elgamal_encrypt(p, g, h, auth_code)

    # 5. Display the encrypted msg, public key, RSA values
    print("\n--- Public information ---")
    print("AES ciphertext (hex)        :", encrypted_content)
    print("ElGamal public key (p, g, h):", (p, g, h))
    print("ElGamal ciphertext          :", elgamal_ciphertext)
    print("RSA public key (n, e)       :", (n, e))

    # 6. Perform hashing on the encrypted msg of AES
    sender_hash = sha256_hash(encrypted_content)
    print("\nSender's hash of AES ciphertext  :", sender_hash)

    # 7. Check the validity of sender and receiver hashing
    with open(encrypted_file, "r") as f:
        received_content = f.read()
    receiver_hash = sha256_hash(received_content)
    print("Receiver's hash of AES ciphertext:", receiver_hash)

    if sender_hash == receiver_hash:
        # 8. If verified, decrypt and show everything
        print("\nIntegrity check PASSED -- proceeding to decrypt")

        recovered_aes_key = rsa_decrypt(private_key, encrypted_key)
        recovered_content = aes_decrypt(recovered_aes_key, received_content)
        recovered_auth_code = elgamal_decrypt(p, x, elgamal_ciphertext)

        print("Recovered AES key           :", recovered_aes_key)
        print("Recovered authorization code:", recovered_auth_code)
        print("Recovered file content      :")
        print(recovered_content)
    else:
        # If integrity failed, don't decrypt, show error output
        print("\nIntegrity check FAILED -- refusing to decrypt")

    # 9. Demonstrate integrity failure: modify one character in the AES ciphertext
    print("\n--- Tampering simulation ---")
    tampered_content = received_content[:-1] + ("0" if received_content[-1] != "0" else "1")

    tampered_hash = sha256_hash(tampered_content)
    print("Hash after tampering:", tampered_hash)

    if sender_hash == tampered_hash:
        print("Integrity check PASSED (unexpected!)")
    else:
        print("Integrity check FAILED -- tampering detected, decryption refused")
