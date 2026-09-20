from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import hashlib
from Crypto.Util.number import getPrime, getRandomRange
import os

def elgamal_generate_keys(bits=256):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 1)   # private key
    h = pow(g, x, p)               # public key component

    return p, g, h, x


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

def read_file(path):
    """The whole file as one string ("" if the file doesn't exist)."""
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path, text):
    """Replaces the file's contents ("w" erases whatever was there)."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def append_file(path, text):
    """Adds to the end of the file, keeping what's already there."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def clear_file(path):
    write_file(path, "")


# ---------- line by line ----------

def read_lines(path):
    """List of lines, newline removed, blank lines skipped ([] if no file)."""
    return [line for line in read_file(path).splitlines() if line.strip()]


def write_lines(path, lines):
    """Replaces the file with one item per line."""
    write_file(path, "".join(str(line) + "\n" for line in lines))


def append_line(path, line):
    append_file(path, str(line) + "\n")


# ---------- records: one record per line, fields joined with "|" ----------
# A field must not contain "|" or a newline.

def append_record(path, fields):
    append_line(path, "|".join(str(field) for field in fields))


def read_records(path):
    """List of records; each record is a list of strings."""
    return [line.split("|") for line in read_lines(path)]


def find_records(path, field_index, value):
    """Every record whose field number `field_index` equals `value`."""
    return [r for r in read_records(path) if r[field_index] == str(value)]

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


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


def tamper_bytes(data):
    """Flips the last byte to simulate corruption/tampering of raw bytes
    (e.g. file content encrypted with file_transfer.py-style bytes-native
    functions)."""
    tampered = bytearray(data)
    tampered[-1] ^= 0xFF

    return bytes(tampered)


def main():
    aes_key=aes_generate_key()
    records_string=read_lines("pat.txt")
    records=read_records("pat.txt")
    for i,r in enumerate(records):
        print(f"[{i}] {r[0]}")
        print(f"[{i}] {r[1]}")
        print(f"[{i}] {r[2]}")
        print(f"[{i}] {r[3]}")
    index=int(input("Choose record to encrypt. ").strip())
    record=records_string[index]
    
    encrypted=aes_encrypt(aes_key,record)
    append_line("pat_enc.txt",encrypted)
    
    hash=sha256_hash(encrypted)
    append_line("pat_hash.txt",hash)
    print("Hash of encrypted record: ",hash)
    
    priv_key, pub_key, n, e, d=rsa_generate_keys()
    enc_aes_key=rsa_encrypt(pub_key,aes_key)
    append_line("pat_rsa_key.txt",enc_aes_key)
    
    auth_code="Auth123"
    p,g,h,x=elgamal_generate_keys()
    enc_auth=elgamal_encrypt(p,g,h,auth_code)
    
    
    print("AES Key: ",aes_key)
    print("AES Encrypted ciphertext: ",encrypted)
    print("SHA-256 Hash : ",hash)
    print("RSA Public Key: ",pub_key)
    print("RSA n: ",n)
    print("RSA e: ",e)
    print("RSA d: ",d)
    print("ELGamal Encrypted Authorisation Code: ",enc_auth)
    
    
    ct=read_lines("pat_enc.txt")[-1]

    read_hash=read_lines("pat_hash.txt")[-1]
    integrity_ok=sha256_hash(ct)==read_hash
    if integrity_ok:
        print("INTEGRITY TEST PASSED")
        read_enc_aes_key=read_lines("pat_rsa_key.txt")[-1]
        dec_aes_key=rsa_decrypt(priv_key,read_enc_aes_key)
        dec_ct=aes_decrypt(dec_aes_key,ct)
        pat_record=dec_ct.split("|")
        print("Decrypted AES Key: ",dec_aes_key)
        print("----Patient Record----")
        print(r[0])
        print(r[1])
        print(r[2])
        print(r[3])
    else:
        print("Integrity check failed. Encrypted patient data has been modified.")
    
    
    #last=ct[-1]
    #new_last=0 if last==1 else 1
    ct_tampered=tamper_bytes(ct.encode())
    new_hash=sha256_hash(ct_tampered.hex())
    new_integrity_ok=new_hash==read_hash
    if not new_integrity_ok:
        print("INTEGRITY FAILURE")
        
if __name__=="__main__":
    main()
    