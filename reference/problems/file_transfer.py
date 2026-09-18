import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------- AES: encrypts the actual file bytes in both schemes ----------

def aes_encrypt_bytes(key, data):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return iv + cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt_bytes(key, data):
    iv, encrypted = data[:AES.block_size], data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(cipher.decrypt(encrypted), AES.block_size)


# ---------- RSA (2048-bit): protects the AES key ----------

def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    return private_key, private_key.public_key()


def rsa_encrypt_key(public_key, aes_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_decrypt_key(private_key, encrypted_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


# ---------- ECC (secp256r1): protects the AES key via ECDH + HKDF ----------

def ecc_generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())

    return private_key, private_key.public_key()


def ecc_derive_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"file transfer").derive(shared_secret)


def ecc_encrypt_key(public_key, aes_key):
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    wrap_key = ecc_derive_key(ephemeral_key, public_key)

    ephemeral_public_bytes = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )

    return ephemeral_public_bytes + aes_encrypt_bytes(wrap_key, aes_key)


def ecc_decrypt_key(private_key, encrypted_key):
    ephemeral_public_bytes, remainder = encrypted_key[:65], encrypted_key[65:]

    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_public_bytes
    )
    wrap_key = ecc_derive_key(private_key, ephemeral_public_key)

    return aes_decrypt_bytes(wrap_key, remainder)


# ---------- benchmark: send `data` using scheme "rsa" or "ecc" ----------

def transfer_file(data, scheme):
    aes_key = get_random_bytes(16)

    generate_keys, encrypt_key, decrypt_key = {
        "rsa": (rsa_generate_keys, rsa_encrypt_key, rsa_decrypt_key),
        "ecc": (ecc_generate_keys, ecc_encrypt_key, ecc_decrypt_key),
    }[scheme]

    t0 = time.perf_counter()
    private_key, public_key = generate_keys()
    keygen_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    encrypted_key = encrypt_key(public_key, aes_key)
    encrypted_data = aes_encrypt_bytes(aes_key, data)
    encrypt_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    recovered_key = decrypt_key(private_key, encrypted_key)
    recovered_data = aes_decrypt_bytes(recovered_key, encrypted_data)
    decrypt_time = time.perf_counter() - t0

    assert recovered_data == data
    return keygen_time, encrypt_time, decrypt_time, len(encrypted_key)


if __name__ == "__main__":
    sizes_mb = [1, 10]

    print(f"{'Size':>6} {'Scheme':>7} {'KeyGen(s)':>10} {'Encrypt(s)':>11} {'Decrypt(s)':>11} {'KeyBytes':>9}")

    for size_mb in sizes_mb:
        data = os.urandom(size_mb * 1024 * 1024)

        for scheme in ("rsa", "ecc"):
            keygen_time, encrypt_time, decrypt_time, key_bytes = transfer_file(data, scheme)
            print(f"{size_mb:>4}MB {scheme:>7} {keygen_time:>10.4f} {encrypt_time:>11.4f} "
                  f"{decrypt_time:>11.4f} {key_bytes:>9}")

    print()
    print("Notes:")
    print("- RSA can't encrypt data larger than its key size, so both schemes use the same")
    print("  approach: AES-128-CBC encrypts the file, and RSA/ECC only encrypt the small AES key.")
    print("  That means file encrypt/decrypt speed is dominated by AES and is ~identical for both;")
    print("  the real difference between RSA and ECC shows up in key generation and key size.")
    print("- RSA-2048 key generation (searching for large primes) is far slower than ECC-secp256r1")
    print("  key generation (picking a random scalar).")
    print("- ECC gives security comparable to RSA at a much smaller key size (256-bit EC keys are")
    print("  roughly as strong as 3072-bit RSA keys), so ECC keys and the wrapped-key ciphertext")
    print("  are smaller, meaning less storage/bandwidth overhead per transfer.")
    print("- RSA security rests on integer factorization; ECC rests on the elliptic curve discrete")
    print("  log problem. Both are considered secure against classical attacks today, but ECC's")
    print("  smaller keys make it the better fit for high-volume or resource-constrained file")
    print("  transfer (mobile, IoT, TLS), while RSA remains simpler to implement and more widely")
    print("  supported by legacy systems.")
