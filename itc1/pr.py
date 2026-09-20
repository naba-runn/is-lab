from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
from Crypto.Util.number import getPrime, getRandomRange
from Crypto.Random import get_random_bytes
from datetime import datetime
import os


def file_exists(path):
    return os.path.exists(path)


# ---------- whole-file read / write ----------

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


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _hash_to_int(message, modulus):
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big") % modulus


def elgamal_generate_keys(bits=256):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 2)   # private key
    y = pow(g, x, p)               # public key

    return p, g, y, x


def elgamal_sign(message, p, g, x):
    while True:
        k = getRandomRange(2, p - 2)
        if pow(k, 1, p - 1) != 0 and _egcd(k, p - 1) == 1:
            break

    h = _hash_to_int(message, p - 1)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)

    return r, s


def elgamal_verify(message, r, s, p, g, y):
    if not (0 < r < p):
        return False

    h = _hash_to_int(message, p - 1)

    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)

    return v1 == v2


def _egcd(a, b):
    while b:
        a, b = b, a % b
    return a


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def des_generate_key():
    return "12345678"


def des_encrypt(key, plaintext,iv=None):
    key_bytes = key.encode() if isinstance(key, str) else key
    iv = iv or get_random_bytes(DES.block_size)
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)

    encrypted = cipher.encrypt(pad(plaintext.encode(), DES.block_size))

    return iv.hex(),(iv+encrypted).hex()


def des_decrypt(key, ciphertext):
    key = bytes.fromhex(key)
    
    raw = bytes.fromhex(ciphertext)
    iv,encrypted=raw[:DES.block_size], raw[DES.block_size:]
    cipher = DES.new(key.encode(), DES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)

    return decrypted.decode()

def client(des_key,p,g,x):
    s=input("Enter confidential record: ")
    
    iv,encrypted=des_encrypt(des_key,s)
    
    hash=sha256_hash(encrypted)
    
    
    r,sign=elgamal_sign(hash,p,g,x)
    time=timestamp()
    print("Ciphertext: ",encrypted)
    print("IV: ", iv)
    print("Hash: ", hash)
    print("ElGamal Signature: ",sign)
    print("Stored at: ",time)
    
    
    append_record("enc.txt",[encrypted,iv,hash,sign,time])
    return r
    
def lawyer(des_key,r,p,g,y):
    record=read_records("enc.txt")[-1]
    hash=sha256_hash(record[0])
    integrity_ok=hash==record[2]
    authentication_ok=elgamal_verify(record[2],r,record[3],p,g,y)
    if integrity_ok:
        print("Integrity test PASSED.") 
        append_line("dec.txt","Integrity test PASSED.")
    else:
        print("Integrity test FAILED.") 
        append_line("dec.txt","Integrity test FAILED.")
    if authentication_ok:
        print("Authentication test PASSED.") 
        append_line("dec.txt","Authentication test PASSED.")
    else:
        print("Authentication test FAILED.") 
        append_line("dec.txt","Authentication test FAILED.")
        
    if integrity_ok and authentication_ok:
        decrypted=des_decrypt(des_key,record[0])
        print("Plaintext: ",decrypted)
    
    append_line("dec.txt","Stored at: "+ timestamp())
    
    
def officer(r,p,g,y):
    record=read_records("enc.txt")[-1]
    hash=sha256_hash(record[0])
    integrity_ok=hash==record[2]
    authentication_ok=elgamal_verify(record[2],r,record[3],p,g,y)
    if integrity_ok:
            print("Integrity test PASSED.") 
            append_line("dec_officer.txt","Integrity test PASSED.")
    else:
            print("Integrity test FAILED.") 
            append_line("dec_officer.txt","Integrity test FAILED.")
    if authentication_ok:
            print("Authentication test PASSED.") 
            append_line("dec_officer.txt","Authentication test PASSED.")
    else:
            print("Authentication test PASSED.") 
            append_line("dec_officer.txt","Authentication test PASSED.")
    
    append_line("dec_officer.txt","Stored at: "+ timestamp())
    
def main():
    des_key=des_generate_key()
    p,g,y,x=elgamal_generate_keys()
    r=0
    while True:
        print("1. Client ")
        print("2. Lawyer ")
        print("3. Compliance Officer ")
        choice=int(input("Enter your choice: "))
        
        if choice==1:
            r=client(des_key,p,g,x)
        elif choice==2:
            lawyer(des_key,r,p,g,y)
        elif choice==3:
            officer(r,p,g,y)
        else:
            print("Enter a valid choice.")

if __name__=="__main__":
    main()
            
        
    
    
    
    
    
    
    
    
    
    

   
    