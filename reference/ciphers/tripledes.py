from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def tripledes_generate_key():
    # 48 hex chars = 24 bytes -> three 8-byte DES keys K1, K2, K3
    return "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"


def _split_key(key_hex):
    raw = bytes.fromhex(key_hex)
    return raw[:8], raw[8:16], raw[16:24]


def _ede_encrypt_block(block, k1, k2, k3):
    block = DES.new(k1, DES.MODE_ECB).encrypt(block)
    block = DES.new(k2, DES.MODE_ECB).decrypt(block)
    block = DES.new(k3, DES.MODE_ECB).encrypt(block)
    return block


def _ede_decrypt_block(block, k1, k2, k3):
    block = DES.new(k3, DES.MODE_ECB).decrypt(block)
    block = DES.new(k2, DES.MODE_ECB).encrypt(block)
    block = DES.new(k1, DES.MODE_ECB).decrypt(block)
    return block


def tripledes_encrypt(key_hex, plaintext):
    k1, k2, k3 = _split_key(key_hex)
    padded = pad(plaintext.encode(), DES.block_size)

    encrypted = b"".join(
        _ede_encrypt_block(padded[i:i + 8], k1, k2, k3)
        for i in range(0, len(padded), 8)
    )
    return encrypted.hex()


def tripledes_decrypt(key_hex, ciphertext):
    k1, k2, k3 = _split_key(key_hex)
    raw = bytes.fromhex(ciphertext)

    decrypted = b"".join(
        _ede_decrypt_block(raw[i:i + 8], k1, k2, k3)
        for i in range(0, len(raw), 8)
    )
    return unpad(decrypted, DES.block_size).decode()


if __name__ == "__main__":
    key = tripledes_generate_key()
    message = "Classified Text"

    ciphertext = tripledes_encrypt(key, message)
    decrypted = tripledes_decrypt(key, ciphertext)

    print("Key (hex)  :", key)
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Decrypted  :", decrypted)

# Note: this assignment's key repeats the same 8-byte block three times
# (K1 = K2 = K3), which makes it cryptographically equivalent to single DES
# (encrypt-then-decrypt-then-encrypt with the same key cancels the middle
# step). The Encrypt-Decrypt-Encrypt structure above is still correct 3DES --
# for real security K1, K2 and K3 should all be different.
