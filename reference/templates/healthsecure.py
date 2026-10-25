# HealthSecure -- exam TEMPLATE
#
# QUESTION
#   Roles: Doctor, Nurse, Admin.
#   Doctor: enter patient details; every field is RSA-encrypted, the SHA-256 of
#           the ciphertext is computed and RSA-signed, with a timestamp.
#           The doctor can view (decrypt) records after they verify.
#   Nurse : verify only (hash + signature), never decrypts.
#   Admin : sees only patient ID, hash and timestamp, and VALID / INVALID.
#
# HOW TO ADAPT -- search for "CHANGE:"
#   - PATIENT_FIELDS: the fields the question lists (each one is encrypted)
#   - file name, role names in main()
#   - RSA-OAEP holds ~190 bytes per field; for long text use hybrid AES+RSA
#     (see templates/hospital.py)
#
# Run:  python healthsecure.py         (menu)
#       python healthsecure.py test    (runs every action with typed-in answers)

import hashlib
import os
import sys
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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

def rsa_message_number(message, n):
    """What is actually signed: SHA-256 of the message as a number, reduced mod n."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % n


def rsa_sign(message, d, n):
    return str(pow(rsa_message_number(message, n), d, n))


def rsa_verify(message, signature, e, n):
    return pow(int(signature), e, n) == rsa_message_number(message, n)


# ---- from ciphers/hashing.py + ciphers/glue_snippets.py (verbatim) ----

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ==================== CHANGE: settings ====================

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(HERE, "health_records.txt")

PATIENT_FIELDS = ["Name", "Age", "Diagnosis"]          # CHANGE: the fields in the question

# one record per line: patient_id|enc field 1|enc field 2|...|hash|signature|time
FIELDS = ["patient_id"] + ["enc_" + f.lower() for f in PATIENT_FIELDS] + ["hash", "signature", "time"]

K = {}


def setup_keys():
    K["priv"], K["pub"], K["n"], K["e"], K["d"] = rsa_generate_keys()
    show("RSA public key n", K["n"])
    show("RSA public key e", K["e"])


def ciphertext_part(rec):
    """What is hashed: all the encrypted fields, in order."""
    return "|".join(rec["enc_" + f.lower()] for f in PATIENT_FIELDS)


def check(rec):
    """(hash_ok, signature_ok) -- no decryption."""
    hash_ok = sha256_hash(ciphertext_part(rec)) == rec["hash"]
    sig_ok = rsa_verify(rec["hash"], rec["signature"], K["e"], K["n"])   # signature string straight from the file
    return hash_ok, sig_ok


# ---------- storage + output helpers ----------

def load_records():
    if not os.path.exists(RECORDS_FILE):
        return []
    with open(RECORDS_FILE, encoding="utf-8") as f:
        return [dict(zip(FIELDS, line.rstrip("\n").split("|"))) for line in f if line.strip()]


def save_records(records):
    with open(RECORDS_FILE, "w", encoding="utf-8") as f:
        for rec in records:
            f.write("|".join(rec[k] for k in FIELDS) + "\n")


def find(pid):
    return next((r for r in load_records() if r["patient_id"] == pid), None)


def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s and "|" not in s:
            return s
        print("Must be non-empty and must not contain '|'.")


def section(title):
    print("\n  " + title.upper() + "\n  " + "-" * len(title))


def show(name, value, width=22):
    text = str(value)
    lines = [text[i:i + 64] for i in range(0, len(text), 64)] or [""]
    print("  " + name.ljust(width) + " : " + ("\n" + " " * (width + 5)).join(lines))


def ok(flag):
    return "PASSED" if flag else "FAILED"


def run_menu(title, options):
    while True:
        print("\n--- " + title + " ---")
        for i, (text, _) in enumerate(options, 1):
            print(str(i) + ". " + text)
        print(str(len(options) + 1) + ". Back")
        choice = input("Choice: ").strip()
        if choice == str(len(options) + 1):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            try:
                options[int(choice) - 1][1]()
            except Exception as e:
                print("Error:", type(e).__name__, e)
        else:
            print("Invalid choice.")


# ==================== roles (CHANGE: actions per role) ====================

def doctor_add():
    pid = ask_text("Patient ID: ")
    if find(pid):
        print("Patient ID already exists.")
        return None
    rec = {"patient_id": pid}
    values = [ask_text(f + ": ") for f in PATIENT_FIELDS]

    section("doctor: encrypting " + pid)
    for field, value in zip(PATIENT_FIELDS, values):
        rec["enc_" + field.lower()] = rsa_encrypt(K["pub"], value)        # each field on its own
        show("RSA(" + field + ")", rec["enc_" + field.lower()])
    rec["hash"] = sha256_hash(ciphertext_part(rec))
    rec["signature"] = rsa_sign(rec["hash"], K["d"], K["n"])
    rec["time"] = timestamp()
    show("SHA-256 of ciphertext", rec["hash"])
    show("RSA signature", rec["signature"])
    show("timestamp", rec["time"])

    with open(RECORDS_FILE, "a", encoding="utf-8") as f:
        f.write("|".join(rec[k] for k in FIELDS) + "\n")
    print("  stored in", RECORDS_FILE)
    return rec


def doctor_view():
    pid = ask_text("Patient ID to view: ")
    rec = find(pid)
    if rec is None:
        print("Not found.")
        return None
    hash_ok, sig_ok = check(rec)
    section("verifying " + pid)
    show("integrity", ok(hash_ok))
    show("signature", ok(sig_ok))
    if not (hash_ok and sig_ok):
        print("  Verification failed -- not decrypting.")
        return None
    section("decrypted patient record")
    values = {}
    for field in PATIENT_FIELDS:
        values[field] = rsa_decrypt(K["priv"], rec["enc_" + field.lower()])
        show(field, values[field])
    return values


def nurse_verify():
    results = {}
    for rec in load_records():
        hash_ok, sig_ok = check(rec)                         # verify only
        section("verifying " + rec["patient_id"])
        show("hash stored", rec["hash"])
        show("hash recomputed", sha256_hash(ciphertext_part(rec)))
        show("integrity", ok(hash_ok))
        show("signature", ok(sig_ok))
        results[rec["patient_id"]] = hash_ok and sig_ok
    return results


def admin_view():
    section("admin view (ID, hash, timestamp only)")
    results = {}
    for rec in load_records():
        hash_ok, sig_ok = check(rec)
        status = "VALID" if hash_ok and sig_ok else "INVALID"
        print("  " + rec["patient_id"].ljust(8) + rec["time"] + "  " + rec["hash"][:32] + "...  " + status)
        results[rec["patient_id"]] = status
    return results


def tamper():
    pid = ask_text("Patient ID to tamper with: ")
    records = load_records()
    for rec in records:
        if rec["patient_id"] == pid:
            key = "enc_" + PATIENT_FIELDS[0].lower()
            rec[key] = rec[key][:-1] + ("0" if rec[key][-1] != "0" else "1")
            save_records(records)
            print("Changed one character of a stored ciphertext.")
            return
    print("Not found.")


def main():
    setup_keys()
    if os.path.exists(RECORDS_FILE):          # new keys each run -> old records could never verify
        os.remove(RECORDS_FILE)
    while True:
        print("\n===== HEALTHSECURE =====")
        print("1. Doctor\n2. Nurse\n3. Admin\n4. (demo) Tamper\n5. Exit")       # CHANGE: role names
        choice = input("Role: ").strip()
        if choice == "1":
            run_menu("Doctor", [("Add patient record", doctor_add), ("Verify and view a record", doctor_view)])
        elif choice == "2":
            run_menu("Nurse", [("Verify all records", nurse_verify)])
        elif choice == "3":
            run_menu("Admin", [("View IDs, hashes, timestamps + VALID/INVALID", admin_view)])
        elif choice == "4":
            tamper()
        elif choice == "5":
            break


# ---------- self-test: python healthsecure.py test ----------

def self_test():
    import builtins
    import tempfile
    global RECORDS_FILE
    RECORDS_FILE = os.path.join(tempfile.mkdtemp(), "r.txt")
    queue = []
    builtins.input = lambda prompt="": (print(prompt + queue[0]) or queue.pop(0))

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()

    setup_keys()
    run(doctor_add, "P1", "Asha", "34", "Flu")
    run(doctor_add, "P2", "Ravi", "51", "Diabetes")
    assert run(doctor_view, "P1") == {"Name": "Asha", "Age": "34", "Diagnosis": "Flu"}
    assert run(nurse_verify) == {"P1": True, "P2": True}
    run(tamper, "P2")
    assert run(admin_view) == {"P1": "VALID", "P2": "INVALID"}
    assert run(doctor_view, "P2") is None
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
