import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


A = string.ascii_lowercase


def vigenere_encrypt(text, key):
    text = ''.join(c for c in text.lower() if c.isalpha())

    return ''.join(
        A[(A.index(c) + A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(text)
    )


def vigenere_decrypt(cipher, key):
    return ''.join(
        A[(A.index(c) - A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(cipher)
    )
    
    
    
    
    
def aes_generate_key():
    return "1234567890123456"


def aes_encrypt(key, plaintext):
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes_decrypt(key, ciphertext):
    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()

    

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

orgtext="PATIENTRECORDSECURE"
vignere_key="HEALTH".lower()

#vignere
c1=vigenere_encrypt(orgtext,vignere_key)
print("vignere ciphertext: ",c1)

#aes
aes_key=aes_generate_key()
c2=aes_encrypt(aes_key,c1)
print("AES ciphertext: ",c2)

#aes key encryption with rsa
rsa_private_key, rsa_public_key,rsa_n, rsa_e, rsa_d=rsa_generate_keys()
c3=rsa_encrypt(rsa_public_key,aes_key)
print("RSA encrypted AES key: ",c3)

#aes key decryption
dec_private_key, dec_public_key,dec_n, dec_e, dec_d=rsa_generate_keys()
p3=rsa_decrypt(rsa_private_key,c3)
print("Recovered AES key: ",p3)

#aes decryption
p2=aes_decrypt(p3,c2)


#vignere decryption
p1=vigenere_decrypt(p2,vignere_key)
print("Fully decrypted plaintext: ",p1)