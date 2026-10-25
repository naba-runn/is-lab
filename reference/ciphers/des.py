from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def des_demo_key():
    # FIXED demo key, not random -- use the key given in the question
    return "12345678"


def des_encrypt(key, plaintext):
    cipher = DES.new(key.encode(), DES.MODE_ECB)

    encrypted = cipher.encrypt(pad(plaintext.encode(), DES.block_size))

    return encrypted.hex()


def des_decrypt(key, ciphertext):
    cipher = DES.new(key.encode(), DES.MODE_ECB)

    decrypted = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), DES.block_size)

    return decrypted.decode()


if __name__ == "__main__":
    key = des_demo_key()
    data = "Hello DES"

    encrypted = des_encrypt(key, data)
    print("Plaintext :", data)
    print("Encrypted :", encrypted)

    decrypted = des_decrypt(key, encrypted)
    print("Decrypted :", decrypted)
