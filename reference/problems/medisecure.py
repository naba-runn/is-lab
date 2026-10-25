import os
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa


# ---------- helpers (not cipher logic, just glue) ----------

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_bytes(text, length):
    """Turns any user-typed string into an exact-length key/IV by truncating
    or zero-padding, so AES never rejects a 'wrong size' key. Use length=16
    for AES-128 (or any cipher's IV), 24 for AES-192, 32 for AES-256."""
    raw = text.encode()[:length]
    return raw.ljust(length, b"\0")


def sha256_hex(data):
    return hashlib.sha256(data.encode()).hexdigest()


# ---- from ciphers/aes.py (verbatim, incl. its optional iv=... param) ----

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


# ---- from ciphers/rsa.py (verbatim) ----

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


# ---- from ciphers/rsa_signature.py (verbatim) ----
# rsa_sign(message, d, n) -> str;  rsa_verify(message, signature, e, n) -> True/False

def rsa_message_number(message, n):
    """What is actually signed: SHA-256 of the message as a number, reduced mod n."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % n


def rsa_sign(message, d, n):
    return str(pow(rsa_message_number(message, n), d, n))


def rsa_verify(message, signature, e, n):
    return pow(int(signature), e, n) == rsa_message_number(message, n)


# ---------- shared in-memory store ----------

records = {}   # filename -> {encrypted, hash, signature, timestamp, verifications}


# ---------- Patient role ----------

def patient_menu(n, d, aes_key, aes_iv):
    while True:
        print("\n--- Patient Menu ---")
        print("1. Upload a medical record (.txt)")
        print("2. View my uploaded records")
        print("3. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            path = input("Path to .txt medical record: ").strip()
            try:
                with open(path, "r") as f:
                    plaintext = f.read()
            except FileNotFoundError:
                print("File not found.")
                continue

            filename = os.path.basename(path)
            encrypted = aes_encrypt(aes_key, plaintext, iv=aes_iv)
            record_hash = sha256_hex(encrypted)
            signature = rsa_sign(record_hash, d, n)

            records[filename] = {
                "encrypted": encrypted,
                "hash": record_hash,
                "signature": signature,
                "timestamp": timestamp(),
                "verifications": [],
            }
            print(f"'{filename}' encrypted, hashed and signed at {records[filename]['timestamp']}")

        elif choice == "2":
            if not records:
                print("No records uploaded yet.")
            for filename, r in records.items():
                print(f"{filename} | hash={r['hash'][:16]}... | uploaded={r['timestamp']}")

        elif choice == "3":
            break


# ---------- Doctor role ----------

def doctor_menu(n, e, aes_key):
    while True:
        print("\n--- Doctor Menu ---")
        print("1. View available records")
        print("2. Decrypt & verify a record")
        print("3. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            for filename in records:
                print(filename)

        elif choice == "2":
            filename = input("Filename to decrypt: ").strip()
            record = records.get(filename)
            if not record:
                print("No such record.")
                continue

            integrity_ok = sha256_hex(record["encrypted"]) == record["hash"]
            authenticity_ok = rsa_verify(record["hash"], record["signature"], e, n)

            print(f"Integrity check   : {'PASSED' if integrity_ok else 'FAILED'}")
            print(f"Authenticity check: {'PASSED' if authenticity_ok else 'FAILED'}")

            record["verifications"].append({
                "result": integrity_ok and authenticity_ok,
                "timestamp": timestamp(),
            })

            if integrity_ok and authenticity_ok:
                plaintext = aes_decrypt(aes_key, record["encrypted"])
                print("Decrypted record:")
                print(plaintext)
            else:
                print("Refusing to display record -- verification failed.")

        elif choice == "3":
            break


# ---------- Auditor role (metadata + signature only, never decrypts) ----------

def auditor_menu(n, e):
    while True:
        print("\n--- Auditor Menu ---")
        print("1. View record metadata")
        print("2. Verify a record's signature")
        print("3. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            for filename, r in records.items():
                print(f"{filename} | hash={r['hash']} | uploaded={r['timestamp']}")

        elif choice == "2":
            filename = input("Filename to verify: ").strip()
            record = records.get(filename)
            if not record:
                print("No such record.")
                continue
            ok = rsa_verify(record["hash"], record["signature"], e, n)
            print("Signature valid:", ok)

        elif choice == "3":
            break


def main():
    print("Generating Patient RSA keypair (2048-bit)...")
    private_key, public_key, n, e, d = rsa_generate_keys()

    aes_key = normalize_bytes(input("Shared AES key: "), 16)
    aes_iv = normalize_bytes(input("Shared AES IV: "), 16)

    while True:
        print("\n=== MediSecure ===")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. Exit")
        choice = input("Select role: ").strip()

        if choice == "1":
            patient_menu(n, d, aes_key, aes_iv)
        elif choice == "2":
            doctor_menu(n, e, aes_key)
        elif choice == "3":
            auditor_menu(n, e)
        elif choice == "4":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
