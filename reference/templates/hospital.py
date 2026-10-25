# Hospital secure file transfer -- exam TEMPLATE
#
# QUESTION
#   Sender  : read a patient file, encrypt it with AES-128, encrypt the AES key
#             with RSA and store it in a file, encrypt an authorization code
#             with ElGamal (GIVEN parameters), hash the ciphertext (SHA-256).
#   Receiver: recompute the hash and compare with the sender's hash; decrypt
#             ONLY if they match (unwrap the AES key with RSA first).
#   Demo    : tamper with the stored ciphertext and show the check fails.
#
# HOW TO ADAPT -- search for "CHANGE:"
#   - ELGAMAL_P / ELGAMAL_G / ELGAMAL_X: the numbers given in the question
#   - AES key size (16 = AES-128, 24 = AES-192, 32 = AES-256)
#   - file names; want a signature too? see templates/healthsecure.py
#
# Run:  python hospital.py         (menu)
#       python hospital.py test    (runs every action with typed-in answers)

import hashlib
import os
import sys
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getRandomRange
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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


# ---- from ciphers/elgamal.py (verbatim) ----

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


# ---- from ciphers/hashing.py + ciphers/glue_snippets.py (verbatim) ----

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ==================== CHANGE: settings ====================

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(HERE, "hospital_records.txt")
WRAPPED_KEY_FILE = os.path.join(HERE, "hospital_aes_key_rsa.txt")    # the RSA-encrypted AES key

AES_KEY_SIZE = 16                                    # CHANGE: 16 = AES-128, 24 = AES-192, 32 = AES-256
ELGAMAL_P, ELGAMAL_G, ELGAMAL_X = 7919, 2, 1234      # CHANGE: p, g, x GIVEN in the question

# one record per line: file_id|ciphertext|enc_auth|hash|time
FIELDS = ["file_id", "ciphertext", "enc_auth", "hash", "time"]

K = {}


def setup_keys():
    K["rsa_priv"], K["rsa_pub"], _, _, _ = rsa_generate_keys()
    K["aes"] = get_random_bytes(AES_KEY_SIZE)
    K["el_h"] = pow(ELGAMAL_G, ELGAMAL_X, ELGAMAL_P)          # public h = g^x mod p
    wrapped = rsa_encrypt(K["rsa_pub"], K["aes"].hex())        # AES key encrypted with RSA ...
    with open(WRAPPED_KEY_FILE, "w", encoding="utf-8") as f:   # ... and stored in a file
        f.write(wrapped)
    show("AES key (hex)", K["aes"].hex())
    show("AES key RSA-encrypted", wrapped)
    show("saved in", WRAPPED_KEY_FILE)
    show("ElGamal p, g, h", (ELGAMAL_P, ELGAMAL_G, K["el_h"]))


def receiver_aes_key():
    """The receiver reads the wrapped key from its file and unwraps it with the RSA private key."""
    with open(WRAPPED_KEY_FILE, encoding="utf-8") as f:
        wrapped = f.read().strip()
    return bytes.fromhex(rsa_decrypt(K["rsa_priv"], wrapped))


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


def find(file_id):
    return next((r for r in load_records() if r["file_id"] == file_id), None)


def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s and "|" not in s:
            return s
        print("Must be non-empty and must not contain '|'.")


def read_text_file(prompt):
    while True:
        path = input(prompt).strip()
        for candidate in (path, os.path.join(HERE, path)):
            if os.path.isfile(candidate):
                with open(candidate, encoding="utf-8") as f:
                    return f.read()
        print("Cannot find", path)


def section(title):
    print("\n  " + title.upper() + "\n  " + "-" * len(title))


def show(name, value, width=22):
    text = str(value)
    lines = [text[i:i + 64] for i in range(0, len(text), 64)] or [""]
    print("  " + name.ljust(width) + " : " + ("\n" + " " * (width + 5)).join(lines))


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


# ==================== roles ====================

def sender_send():
    file_id = ask_text("File ID: ")
    if find(file_id):
        print("File ID already exists.")
        return None
    content = read_text_file("Patient file (.txt): ")
    auth_code = ask_text("Authorization code: ")

    section("sender: " + file_id)
    rec = {"file_id": file_id}
    rec["ciphertext"] = aes_encrypt(K["aes"], content)                       # AES-128-CBC, random IV
    rec["enc_auth"] = elgamal_encrypt(ELGAMAL_P, ELGAMAL_G, K["el_h"], auth_code)
    rec["hash"] = sha256_hash(rec["ciphertext"])
    rec["time"] = timestamp()
    show("AES ciphertext (hex)", rec["ciphertext"])
    show("ElGamal(auth code)", rec["enc_auth"])
    show("SHA-256 (sender)", rec["hash"])
    show("timestamp", rec["time"])
    with open(RECORDS_FILE, "a", encoding="utf-8") as f:
        f.write("|".join(rec[k] for k in FIELDS) + "\n")
    print("  stored in", RECORDS_FILE)
    return rec


def receiver_open():
    file_id = ask_text("File ID to receive: ")
    rec = find(file_id)
    if rec is None:
        print("Not found.")
        return None
    section("receiver: integrity check")
    receiver_hash = sha256_hash(rec["ciphertext"])
    show("sender hash", rec["hash"])
    show("receiver hash", receiver_hash)
    if receiver_hash != rec["hash"]:
        print("  HASH MISMATCH -- file was altered, NOT decrypted.")
        return None
    print("  hashes match -> decrypting")
    key = receiver_aes_key()
    show("AES key unwrapped (hex)", key.hex())
    content = aes_decrypt(key, rec["ciphertext"])
    auth_code = elgamal_decrypt(ELGAMAL_P, ELGAMAL_X, rec["enc_auth"])
    section("decrypted file")
    print("\n".join("    " + line for line in content.splitlines()))
    show("authorization code", auth_code)
    return content, auth_code


def tamper():
    file_id = ask_text("File ID to tamper with: ")
    records = load_records()
    for rec in records:
        if rec["file_id"] == file_id:
            c = rec["ciphertext"]
            rec["ciphertext"] = c[:-1] + ("0" if c[-1] != "0" else "1")
            save_records(records)
            print("Changed one character of the stored ciphertext.")
            return
    print("Not found.")


def main():
    setup_keys()
    if os.path.exists(RECORDS_FILE):
        os.remove(RECORDS_FILE)
    while True:
        print("\n===== HOSPITAL SECURE TRANSFER =====")
        print("1. Sender\n2. Receiver\n3. (demo) Tamper\n4. Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            run_menu("Sender", [("Encrypt and send a patient file", sender_send)])
        elif choice == "2":
            run_menu("Receiver", [("Check hash and decrypt a file", receiver_open)])
        elif choice == "3":
            tamper()
        elif choice == "4":
            break


# ---------- self-test: python hospital.py test ----------

def self_test():
    import builtins
    import tempfile
    global RECORDS_FILE, WRAPPED_KEY_FILE
    tmp = tempfile.mkdtemp()
    RECORDS_FILE, WRAPPED_KEY_FILE = os.path.join(tmp, "r.txt"), os.path.join(tmp, "k.txt")
    report = os.path.join(tmp, "report.txt")
    with open(report, "w", encoding="utf-8") as f:
        f.write("Patient: Asha\nBP 120/80\n")
    queue = []
    builtins.input = lambda prompt="": (print(prompt + queue[0]) or queue.pop(0))

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()

    setup_keys()
    run(sender_send, "F1", report, "AUTH-77")
    run(sender_send, "F2", report, "AUTH-88")
    assert run(receiver_open, "F1") == ("Patient: Asha\nBP 120/80\n", "AUTH-77")
    run(tamper, "F2")
    assert run(receiver_open, "F2") is None
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
