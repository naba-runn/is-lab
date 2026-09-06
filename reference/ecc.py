from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def ecc_generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"ecc encryption"
    ).derive(shared_secret)


def ecc_encrypt(public_key, plaintext):
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    aes_key = derive_shared_key(ephemeral_key, public_key)

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    ephemeral_public_bytes = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    return (ephemeral_public_bytes + iv + encrypted).hex()


def ecc_decrypt(private_key, ciphertext):
    raw = bytes.fromhex(ciphertext)

    ephemeral_public_bytes = raw[:65]
    iv = raw[65:65 + AES.block_size]
    encrypted = raw[65 + AES.block_size:]

    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_public_bytes
    )
    aes_key = derive_shared_key(private_key, ephemeral_public_key)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


if __name__ == "__main__":
    private_key, public_key = ecc_generate_keys()

    message = "Secure Transactions"

    ciphertext = ecc_encrypt(public_key, message)
    decrypted = ecc_decrypt(private_key, ciphertext)

    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)

# ECC doesn't encrypt directly: an ephemeral EC key is used with the recipient's
# public key (ECDH) to derive a one-time AES key (ECIES), which then does the
# actual encryption. The ephemeral public key travels with the ciphertext so the
# recipient can redo the same ECDH step with their private key.
