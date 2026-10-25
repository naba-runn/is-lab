# MediSecure -- exam TEMPLATE
#
# QUESTION
#   Roles: Patient, Doctor, Auditor.
#   Patient: upload a medical record (.txt). It is AES-encrypted with a key and
#            IV the USER types, SHA-256 hashed, RSA-signed, timestamped, stored.
#   Doctor : verify hash + signature, then decrypt and read the record.
#   Auditor: verify signatures and see metadata only (never decrypts).
#
# HOW TO ADAPT -- search for "CHANGE:"
#   - AES size: KEY_SIZE 16 / 24 / 32  (AES-128 / 192 / 256)
#   - key/IV typed once at start (as asked); random IV per record is one line
#   - file names, role names in main()
#
# Run:  python medisecure.py         (menu)
#       python medisecure.py test    (runs every action with typed-in answers)

import hashlib
import os
import sys
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa


# ---- from ciphers/aes.py (verbatim) ----

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


# ---- from ciphers/rsa.py + ciphers/rsa_signature.py (verbatim) ----

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


def normalize_bytes(text, length):
    """Turns any user-typed string into an exact-length key/IV by truncating
    or zero-padding, so AES never rejects a 'wrong size' key. Use length=16
    for AES-128 (or any cipher's IV), 24 for AES-192, 32 for AES-256."""
    raw = text.encode()[:length]
    return raw.ljust(length, b"\0")


# ==================== CHANGE: settings ====================

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(HERE, "medisecure_records.txt")
LOG_FILE = os.path.join(HERE, "medisecure_log.txt")

KEY_SIZE = 16                                      # CHANGE: 16 = AES-128, 24 = AES-192, 32 = AES-256

# one record per line: filename|ciphertext|hash|signature|time
FIELDS = ["filename", "ciphertext", "hash", "signature", "time"]

K = {}


def setup_keys():
    K["aes"] = normalize_bytes(input("AES key (any text): "), KEY_SIZE)    # CHANGE: key typed by the user
    K["iv"] = normalize_bytes(input("AES IV (any text): "), 16)            # CHANGE: IV typed (None -> random per record)
    K["priv"], K["pub"], K["n"], K["e"], K["d"] = rsa_generate_keys()
    show("AES key (hex)", K["aes"].hex())
    show("AES IV (hex)", K["iv"].hex())
    show("RSA public key n", K["n"])


def check(rec):
    hash_ok = sha256_hash(rec["ciphertext"]) == rec["hash"]
    sig_ok = rsa_verify(rec["hash"], rec["signature"], K["e"], K["n"])
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


def find(name):
    return next((r for r in load_records() if r["filename"] == name), None)


def log(role, action, name, status):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(timestamp() + "|" + role + "|" + action + "|" + name + "|" + status + "\n")


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

def patient_upload():
    path = ask_text("Path to the .txt medical record: ")
    if not os.path.isfile(path):
        path = os.path.join(HERE, path)
    if not os.path.isfile(path):
        print("File not found.")
        return None
    name = os.path.basename(path)
    if find(name):
        print(name, "is already uploaded.")
        return None
    with open(path, encoding="utf-8") as f:
        content = f.read()

    section("patient: uploading " + name)
    rec = {"filename": name}
    rec["ciphertext"] = aes_encrypt(K["aes"], content, K["iv"])
    rec["hash"] = sha256_hash(rec["ciphertext"])
    rec["signature"] = rsa_sign(rec["hash"], K["d"], K["n"])
    rec["time"] = timestamp()
    show("AES ciphertext (hex)", rec["ciphertext"])
    show("SHA-256", rec["hash"])
    show("RSA signature", rec["signature"])
    show("timestamp", rec["time"])
    with open(RECORDS_FILE, "a", encoding="utf-8") as f:
        f.write("|".join(rec[k] for k in FIELDS) + "\n")
    log("Patient", "upload", name, "OK")
    return rec


def patient_list():
    for rec in load_records():
        print("  " + rec["filename"].ljust(20) + rec["time"] + "  " + rec["hash"][:24] + "...")


def doctor_read():
    name = ask_text("Filename to read: ")
    rec = find(name)
    if rec is None:
        print("Not found.")
        return None
    hash_ok, sig_ok = check(rec)
    section("doctor: verifying " + name)
    show("integrity", ok(hash_ok))
    show("authenticity", ok(sig_ok))
    if not (hash_ok and sig_ok):
        print("  Verification failed -- NOT decrypted.")
        log("Doctor", "read", name, "DENIED")
        return None
    content = aes_decrypt(K["aes"], rec["ciphertext"])
    section("decrypted record")
    print("\n".join("    " + line for line in content.splitlines()))
    log("Doctor", "read", name, "GRANTED")
    return content


def auditor_audit():
    section("auditor: metadata + signature check (no decryption)")
    results = {}
    for rec in load_records():
        hash_ok, sig_ok = check(rec)
        status = "VALID" if hash_ok and sig_ok else "INVALID"
        print("  " + rec["filename"].ljust(20) + rec["time"] + "  signature " + ok(sig_ok)
              + "  hash " + ok(hash_ok) + "  -> " + status)
        results[rec["filename"]] = status
    log("Auditor", "audit", "-", str(results))
    return results


def tamper():
    name = ask_text("Filename to tamper with: ")
    records = load_records()
    for rec in records:
        if rec["filename"] == name:
            c = rec["ciphertext"]
            rec["ciphertext"] = c[:-1] + ("0" if c[-1] != "0" else "1")
            save_records(records)
            print("Changed one character of the stored ciphertext.")
            return
    print("Not found.")


def main():
    setup_keys()
    for path in (RECORDS_FILE, LOG_FILE):
        if os.path.exists(path):
            os.remove(path)
    while True:
        print("\n===== MEDISECURE =====")
        print("1. Patient\n2. Doctor\n3. Auditor\n4. (demo) Tamper\n5. Exit")   # CHANGE: role names
        choice = input("Role: ").strip()
        if choice == "1":
            run_menu("Patient", [("Upload a .txt medical record", patient_upload), ("List my records", patient_list)])
        elif choice == "2":
            run_menu("Doctor", [("Verify and read a record", doctor_read)])
        elif choice == "3":
            run_menu("Auditor", [("Audit all records", auditor_audit)])
        elif choice == "4":
            tamper()
        elif choice == "5":
            break


# ---------- self-test: python medisecure.py test ----------

def self_test():
    import builtins
    import tempfile
    global RECORDS_FILE, LOG_FILE
    tmp = tempfile.mkdtemp()
    RECORDS_FILE, LOG_FILE = os.path.join(tmp, "r.txt"), os.path.join(tmp, "l.txt")
    for name, text in (("rec1.txt", "BP 120/80\nmild fever\n"), ("rec2.txt", "Sugar 140\n")):
        with open(os.path.join(tmp, name), "w", encoding="utf-8") as f:
            f.write(text)
    queue = []
    builtins.input = lambda prompt="": (print(prompt + queue[0]) or queue.pop(0))

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()

    run(setup_keys, "mykey", "myiv")
    run(patient_upload, os.path.join(tmp, "rec1.txt"))
    run(patient_upload, os.path.join(tmp, "rec2.txt"))
    run(patient_list)
    assert run(doctor_read, "rec1.txt") == "BP 120/80\nmild fever\n"
    run(tamper, "rec2.txt")
    assert run(auditor_audit) == {"rec1.txt": "VALID", "rec2.txt": "INVALID"}
    assert run(doctor_read, "rec2.txt") is None
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
