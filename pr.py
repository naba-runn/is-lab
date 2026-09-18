import hashlib
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# ---- from ciphers/rsa.py (verbatim) ----

def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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


# ---- from ciphers/rsa_signature.py (verbatim) ----

def rsa_sign(message, d, n):
    m = int.from_bytes(message.encode(), "big")
    return pow(m, d, n)


def rsa_verify(signature, e, n):
    m = pow(signature, e, n)
    length = (m.bit_length() + 7) // 8

    return m.to_bytes(length, "big").decode(errors="replace")


# ---- from ciphers/hashing.py (verbatim) ----

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ---- from ciphers/glue_snippets.py (verbatim) ----

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---- from CHEATSHEET.py's record-building patterns ----

def build_record(*fields):
    return "|".join(str(field) for field in fields)


def parse_record(record_string):
    return record_string.split("|")


def make_record(encrypted_text, **extra_fields):
    record = {"encrypted": encrypted_text}
    record.update(extra_fields)
    return record


def write_record_to_file(filename, record):
    with open(filename, "a") as f:
        f.write(json.dumps(record) + "\n")


def read_records_from_file(filename):
    records = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


PATIENTS_FILE = "patients.jsonl"


# ---------- Doctor role ----------

def doctor_menu(public_key, private_key, e, n, d):
    while True:
        print("\n--- Doctor Menu ---")
        print("1. Enter a new patient record")
        print("2. View previously stored records")
        print("3. Decrypt & verify a record")
        print("4. Back")
        choice = input("Choice: ").strip()

        if choice == "1":
            name = input("Name: ")
            age = input("Age: ")
            gender = input("Gender: ")
            blood_group = input("Blood group: ")
            diagnosis = input("Diagnosis: ")

            # Concatenate the fields into one string, then run it through
            # the same encrypt -> hash -> sign pipeline as any other message.
            # (RSA-OAEP with a 2048-bit key tops out around ~190 bytes --
            # comfortably enough for these fields, but a much longer
            # diagnosis would need the hybrid AES+RSA pattern instead, see
            # file_transfer.py / hospital_management.py.)
            plaintext = build_record(name, age, gender, blood_group, diagnosis)

            encrypted = rsa_encrypt(public_key, plaintext)
            record_hash = sha256_hash(encrypted)
            signature = rsa_sign(record_hash, d, n)

            record = make_record(
                encrypted,
                hash=record_hash,
                signature=signature,
                timestamp=timestamp(),
            )
            write_record_to_file(PATIENTS_FILE, record)
            print(f"Patient record stored at {record['timestamp']}")

        elif choice == "2":
            records = read_records_from_file(PATIENTS_FILE)
            if not records:
                print("No records stored yet.")
            for i, r in enumerate(records):
                print(f"[{i}] hash={r['hash'][:16]}... | stored={r['timestamp']}")

        elif choice == "3":
            records = read_records_from_file(PATIENTS_FILE)
            if not records:
                print("No records stored yet.")
                continue

            for i, r in enumerate(records):
                print(f"[{i}] hash={r['hash'][:16]}... | stored={r['timestamp']}")

            try:
                index = int(input("Record number to decrypt: ").strip())
                record = records[index]
            except (ValueError, IndexError):
                print("No such record.")
                continue

            integrity_ok = sha256_hash(record["encrypted"]) == record["hash"]
            authenticity_ok = rsa_verify(record["signature"], e, n) == record["hash"]

            print(f"Integrity check   : {'PASSED' if integrity_ok else 'FAILED'}")
            print(f"Authenticity check: {'PASSED' if authenticity_ok else 'FAILED'}")

            if integrity_ok and authenticity_ok:
                plaintext = rsa_decrypt(private_key, record["encrypted"])
                name, age, gender, blood_group, diagnosis = parse_record(plaintext)

                print("\nDecrypted patient information:")
                print("  Name        :", name)
                print("  Age         :", age)
                print("  Gender      :", gender)
                print("  Blood group :", blood_group)
                print("  Diagnosis   :", diagnosis)
            else:
                print("Refusing to display record -- verification failed.")

        elif choice == "4":
            break


# ---------- Nurse / Admin roles ----------
# Only the Doctor's requirements were specified for this question. Add
# Nurse's and Admin's own menu functions here following the exact same
# shape as doctor_menu() above once their requirements are known -- e.g. a
# Nurse might get read-only access to metadata (like MediSecure's Auditor:
# view hash/timestamp, verify the signature, but never call rsa_decrypt),
# and an Admin might get user/key management (like secure_corp.py's
# KeyManager: register/revoke).

def nurse_menu():
    print("Nurse role not yet specified for this question.")


def admin_menu():
    print("Admin role not yet specified for this question.")


def main():
    print("Generating Doctor's RSA keypair (2048-bit)...")
    private_key, public_key, n, e, d = rsa_generate_keys()
    # Generated ONCE here and reused for every patient record -- this is
    # what makes every record encrypted with the same key decryptable
    # later. (Restarting the program loses this key, same as
    # medisecure.py's Patient key -- records already on disk can still be
    # LISTED, but not decrypted, after a restart, since the private key
    # was never written to disk. That's expected here since the question
    # doesn't ask for key persistence across sessions.)

    while True:
        print("\n=== HealthSecure ===")
        print("1. Doctor")
        print("2. Nurse")
        print("3. Admin")
        print("4. Exit")
        choice = input("Select role: ").strip()

        if choice == "1":
            doctor_menu(public_key, private_key, e, n, d)
        elif choice == "2":
            nurse_menu()
        elif choice == "3":
            admin_menu()
        elif choice == "4":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
