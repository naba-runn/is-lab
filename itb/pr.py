from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes



def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def rsa_sign(message, d, n):
    m = int.from_bytes(message.encode(), "big")
    signature = pow(m, d, n)

    return signature


def rsa_verify(signature, e, n):
    m = pow(signature, e, n)
    length = (m.bit_length() + 7) // 8

    return m.to_bytes(length, "big").decode(errors="replace")

def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    numbers = private_key.private_numbers()

    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d

    return private_key, public_key, n, e, d

def append_file(path, text):
    """Adds to the end of the file, keeping what's already there."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)

def append_line(path, line):
    append_file(path, str(line) + "\n")


def read_file(path):
    """The whole file as one string ("" if the file doesn't exist)."""
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
    
    
def read_lines(path):
    """List of lines, newline removed, blank lines skipped ([] if no file)."""
    return [line for line in read_file(path).splitlines() if line.strip()]

def append_record(path, fields):
    append_line(path, ",".join(str(field) for field in fields))

def read_records(path):
    """List of records; each record is a list of strings."""
    return [line.split(",") for line in read_lines(path)]


def patient_menu(aes_key, iv, d, n):
    while True:
        print("-----Patient's Menu-----")
        print("1. Read record and encrypt.")
        print("2. Read encrypted records.")
        print("3. Exit")
        choice=int(input("Enter your choice.").strip())
        
        if choice==1:
            rec = read_lines("pat.txt")
            record=rec[0]
            encrypted = aes_encrypt(aes_key, record, iv)
            hash1=sha256_hash(encrypted)
            sign=rsa_sign(hash1,d,n)
            append_record("pat_enc.txt",[encrypted,hash1,sign,iv,timestamp()])
            
        elif choice==2:
            recs=read_records("pat_enc.txt")
            rec=recs[-1]
            print("Encrypted record: ",rec[0])
            print("Hash: ",rec[1])
            print("Stored at: ", rec[-1])
        elif choice==3:
            break
    
def doctor_menu(aes_key, e, n):
    while True:
        print("-----Doctor's Menu-----")
        print("1. Read encrypted records.")
        print("2. Read record and decrypt.")
        print("3. Exit")
        choice=int(input("Enter your choice.").strip())
        
        if choice==1:
            recs=read_records("pat_enc.txt")
            for i, r in enumerate(recs):
                print(f"[{i}] encrypted record={r[0]} | hash={r[1][:16]}... | stored={r[-1]}")
        elif choice==2:
            recs=read_records("pat_enc.txt")
            for i, r in enumerate(recs):
                print(f"[{i}] encrypted record={r[0]} | hash={r[1][:16]}... | stored={r[-1]}")
            index=int(input("Choose record index").strip())
            rec=recs[index]
            enc_record=rec[0]
            hash=rec[1]
            sign=int(rec[2])
            decrypted_record=aes_decrypt(aes_key,enc_record)
            integrity_ok=sha256_hash(enc_record)==hash
            authenticity_ok=rsa_verify(sign,e,n)==hash
            if integrity_ok and authenticity_ok:
                enc_rec=decrypted_record.split("|")
                print("Name: ",enc_rec[0])
                print("Age: ",enc_rec[1])
                print("Gender: ",enc_rec[2])
                print("Diag: ",enc_rec[3])
                append_line("pat_dec.txt",f"Tests passed for record {index}")

            else:
                print("Test failed")
                append_line("pat_dec.txt",f"Tests failed for record {index}")
            
        elif choice==3:
            break
            
def admin_menu(e,n):
    while True:
        print("-----Doctor's Menu-----")
        print("1. Read encrypted records.")
        print("2. Read record and decrypt.")
        print("3. Exit")
        choice=int(input("Enter your choice.").strip())
                   
        if choice==1:
            recs=read_records("pat_enc.txt")
            for i, r in enumerate(recs):
                print(f"[{i}] hash={r[1][:16]}... | stored={r[-1]}")
        elif choice==2:
            recs=read_records("pat_enc.txt")
            for i, r in enumerate(recs):
                print(f"[{i}] hash={r[1][:16]}... | stored={r[-1]}")
            index=int(input("Enter your choice").strip())
            rec=recs[index]
            authenticity_ok=rsa_verify(int(rec[2]),e,n)==rec[1]
            if authenticity_ok:
                print("Authenticity test passed")
            else: 
                print("failed")
                
def main():     
    priv_key, pub_key, n, e, d=rsa_generate_keys()
    aes_key=aes_generate_key()
    iv = get_random_bytes(AES.block_size)        
    while True:
            
            print("\n=== HealthSecure ===")
            print("1. Patient")
            print("2. Doctor")
            print("3. Admin")
            print("4. Exit")
            choice = input("Select role: ").strip()

            if choice == "1":
                patient_menu(aes_key,iv,d,n)
            elif choice == "2":
                doctor_menu(aes_key,e,n)
            elif choice == "3":
                admin_menu(e,n)
            elif choice == "4":
                break
            else:
                print("Invalid choice.")


if __name__ == "__main__":
    main()
