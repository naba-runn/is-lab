from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"12345678"
data = b"Hello DES"

# Encryption
cipher = DES.new(key, DES.MODE_ECB)

encrypted = cipher.encrypt(pad(data, DES.block_size))

print("Plaintext :", data)
print("Encrypted :", encrypted.hex())

# Decryption
cipher = DES.new(key, DES.MODE_ECB)

decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)

print("Decrypted :", decrypted.decode())