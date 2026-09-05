from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = b"1234567890123456"
data = b"Hello AES"

# Encryption
iv = get_random_bytes(AES.block_size)

cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(data, AES.block_size))

print("Plaintext :", data)
print("Encrypted :", encrypted.hex())

# Decryption
cipher = AES.new(key, AES.MODE_CBC, iv)

decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

print("Decrypted :", decrypted.decode())