# Role-based "secure portal" TEMPLATE (worked example: Secure Grant Expense Portal).
#
# Researcher : enter ID + description + amount -> AES-192(desc), Paillier(amount),
#              MD5(record), RSA-sign(hash), append to file; view all records.
# Reviewer   : verify signature + recompute hash, search by ID (no ciphertext
#              shown), decrypt description as a hex dump.
# Officer    : pick IDs, verify each, add the Paillier ciphertexts, decrypt ONLY
#              the total.
#
# HOW TO REUSE IN THE EXAM
#   1. Copy this file, run it once (it works as-is).
#   2. EDIT ZONE 1: swap the crypto (one line per slot).
#   3. EDIT ZONE 2: rename the prompts / fields.
#   4. EDIT ZONE 3: add or remove role menu options.
#   Everything below "plumbing" never needs touching.
#
# Rules that prevent the usual bugs:
#   - keys are module globals, loaded once -> no function takes a key argument
#   - keys are saved in keys.txt -> old records still verify after a restart
#   - IDs stay strings; int() happens only inside the crypto zone
#   - every menu action is wrapped in safe() -> one bug never kills the menu
#
# Run:  python portal_template.py         (menu)
#       python portal_template.py test    (automatic self-test, temp files)

import os
import sys
import math
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, getRandomRange
from cryptography.hazmat.primitives.asymmetric import rsa


HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(HERE, "records.txt")
KEYS_FILE = os.path.join(HERE, "keys.txt")


# ---------- from ciphers/aes192.py ----------

def aes192_generate_key():
    # 48 hex chars = 24 bytes -> AES-192
    return "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"


def aes192_encrypt(key_hex, plaintext):
    key = bytes.fromhex(key_hex)

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return (iv + encrypted).hex()


def aes192_decrypt(key_hex, ciphertext):
    key = bytes.fromhex(key_hex)

    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


# ---------- from ciphers/paillier.py ----------

def paillier_generate_keys(bits=1024):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p != q and math.gcd(p * q, (p - 1) * (q - 1)) == 1:
            break

    n = p * q
    g = n + 1
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)       # lcm(p-1, q-1)
    mu = pow((pow(g, lam, n * n) - 1) // n, -1, n)

    return n, g, lam, mu


def paillier_encrypt(n, g, message):
    n2 = n * n

    while True:
        r = getRandomRange(1, n)
        if math.gcd(r, n) == 1:
            break

    return (pow(g, message, n2) * pow(r, n, n2)) % n2


def paillier_decrypt(n, lam, mu, ciphertext):
    l = (pow(ciphertext, lam, n * n) - 1) // n

    return (l * mu) % n


def paillier_add(n, c1, c2):
    return (c1 * c2) % (n * n)


# ---------- from ciphers/rsa.py + ciphers/rsa_signature.py ----------

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


def rsa_sign(message, d, n):
    m = int.from_bytes(message.encode(), "big")
    signature = pow(m, d, n)

    return signature


def rsa_verify(signature, e, n):
    m = pow(signature, e, n)
    length = (m.bit_length() + 7) // 8

    return m.to_bytes(length, "big").decode(errors="replace")


# ---------- from ciphers/hashing.py ----------

def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ---------- keys: generated once, saved, loaded on every later run ----------

def load_or_create_keys():
    """keys.txt holds one name=value per line. Delete it to get fresh keys
    (but then old records can no longer be verified or decrypted)."""
    if not os.path.exists(KEYS_FILE):
        print("First run: generating keys (a few seconds)...")
        p_n, p_g, p_lam, p_mu = paillier_generate_keys()
        _, _, r_n, r_e, r_d = rsa_generate_keys()
        keys = {"aes": aes192_generate_key(),
                "p_n": p_n, "p_g": p_g, "p_lam": p_lam, "p_mu": p_mu,
                "r_n": r_n, "r_e": r_e, "r_d": r_d}
        with open(KEYS_FILE, "w", encoding="utf-8") as f:
            for name, value in keys.items():
                f.write(name + "=" + str(value) + "\n")

    keys = {}
    with open(KEYS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if "=" in line:
                name, value = line.strip().split("=", 1)
                keys[name] = value if name == "aes" else int(value)
    return keys


K = None          # filled by main() / self_test() via load_or_create_keys()


# ==================== EDIT ZONE 1: which crypto ====================
# Every crypto call in the program goes through these six lines.
# Ciphertexts/signatures are stored as strings, so int() happens HERE only.

def enc_text(s):          return aes192_encrypt(K["aes"], s)
def dec_text(c):          return aes192_decrypt(K["aes"], c)
def enc_num(x):           return str(paillier_encrypt(K["p_n"], K["p_g"], x))
def hash_fn(s):           return md5_hash(s)                    # or sha256_hash
def sign(h):              return str(rsa_sign(h, K["r_d"], K["r_n"]))
def verify_sig(sig, h):   return rsa_verify(int(sig), K["r_e"], K["r_n"]) == h


def add_encrypted(cipher_strings):
    """Homomorphic sum of Paillier ciphertexts (strings) -> Paillier int."""
    total = paillier_encrypt(K["p_n"], K["p_g"], 0)
    for c in cipher_strings:
        total = paillier_add(K["p_n"], total, int(c))
    return total


def dec_total(total):     return paillier_decrypt(K["p_n"], K["p_lam"], K["p_mu"], total)


# ==================== EDIT ZONE 2: what a record is ====================
# One line per record in records.txt:  id|enc_desc|enc_amt|hash|sig
# The hash covers id + both ciphertexts, so editing ANY of them is detected.

def make_record(rec_id, desc, amount):
    enc_desc = enc_text(desc)
    enc_amt = enc_num(amount)
    h = hash_fn(rec_id + "," + enc_desc + "," + enc_amt)
    return {"id": rec_id, "enc_desc": enc_desc, "enc_amt": enc_amt,
            "hash": h, "sig": sign(h)}


def hashed_part(rec):
    return rec["id"] + "," + rec["enc_desc"] + "," + rec["enc_amt"]


FIELDS = ["id", "enc_desc", "enc_amt", "hash", "sig"]


# ---------- plumbing: file storage ----------

def load_records():
    records = []
    if not os.path.exists(RECORDS_FILE):
        return records
    with open(RECORDS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == len(FIELDS):
                records.append(dict(zip(FIELDS, parts)))
            elif line.strip():
                print("Skipping damaged line in file.")
    return records


def save_records(records):
    with open(RECORDS_FILE, "w", encoding="utf-8") as f:
        for rec in records:
            f.write("|".join(rec[k] for k in FIELDS) + "\n")


def append_record(rec):
    with open(RECORDS_FILE, "a", encoding="utf-8") as f:
        f.write("|".join(rec[k] for k in FIELDS) + "\n")


def find_record(rec_id):
    """The record with this ID, or None. IDs are compared as strings."""
    for rec in load_records():
        if rec["id"] == rec_id:
            return rec
    return None


def check_record(rec):
    """(hash_ok, sig_ok) -- never raises, even on garbage."""
    try:
        hash_ok = hash_fn(hashed_part(rec)) == rec["hash"]
    except Exception:
        hash_ok = False
    try:
        sig_ok = verify_sig(rec["sig"], rec["hash"])
    except Exception:
        sig_ok = False
    return hash_ok, sig_ok


# ---------- plumbing: input + output helpers ----------

def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s and "|" not in s and "," not in s:
            return s
        print("Must be non-empty and contain no '|' or ','.")


def ask_int(prompt, minimum=0):
    while True:
        s = input(prompt).strip()
        try:
            value = int(s)
            if value >= minimum:
                return value
        except ValueError:
            pass
        print("Enter a whole number >=", minimum)


def ask_ids(prompt):
    """'1, 3,4' -> ['1', '3', '4'];  'all' -> every stored ID."""
    s = input(prompt).strip()
    if s.lower() == "all":
        return [r["id"] for r in load_records()]
    return [x.strip() for x in s.split(",") if x.strip()]


def hexdump(text):
    data = text.encode()
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join("%02x" % b for b in chunk)
        text_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %-47s  |%s|" % (i, hex_part, text_part))
    return "\n".join(lines)


def short(s, n=20):
    return s if len(s) <= n else s[:n] + "..."


def show(rec):
    print("ID:", rec["id"], "| desc:", short(rec["enc_desc"]),
          "| amount:", short(rec["enc_amt"]), "| hash:", rec["hash"],
          "| sig:", short(rec["sig"]))


def label(ok):
    return "OK" if ok else "FAILED"


def safe(fn):
    """Wrap a menu action: an exception prints instead of crashing the menu."""
    def run():
        try:
            fn()
        except Exception as e:
            print("Error:", type(e).__name__, e)
    return run


def run_menu(title, options, back_label="Back"):
    # from system_parts/role_menu.py
    while True:
        print("\n--- " + title + " ---")
        for number, (text, _) in enumerate(options, start=1):
            print(str(number) + ". " + text)
        print(str(len(options) + 1) + ". " + back_label)

        choice = input("Choice: ").strip()

        if choice == str(len(options) + 1):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            safe(options[int(choice) - 1][1])()
        else:
            print("Invalid choice.")


# ==================== EDIT ZONE 3: role actions ====================

# ----- researcher -----

def researcher_submit():
    rec_id = ask_text("Grant ID: ")
    if find_record(rec_id):
        print("Grant ID", rec_id, "already exists.")
        return
    desc = ask_text("Grant description: ")
    amount = ask_int("Grant amount: ")

    rec = make_record(rec_id, desc, amount)
    append_record(rec)
    print("Stored. AES-192 desc:", short(rec["enc_desc"], 40))
    print("        Paillier amt:", short(rec["enc_amt"], 40))
    print("        MD5 hash    :", rec["hash"])
    print("        RSA sig     :", short(rec["sig"], 40))


def view_all():
    records = load_records()
    if not records:
        print("No records yet.")
    for rec in records:
        show(rec)


# ----- reviewer -----

def reviewer_verify():
    records = load_records()
    if not records:
        print("No records yet.")
    for rec in records:
        hash_ok, sig_ok = check_record(rec)
        status = "VALID" if hash_ok and sig_ok else "TAMPERED"
        print("ID", rec["id"], "-> hash", label(hash_ok), "| signature", label(sig_ok), "->", status)


def reviewer_search():
    rec = find_record(ask_text("Search Grant ID: "))
    if rec is None:
        print("Not found.")
        return
    hash_ok, sig_ok = check_record(rec)
    # index lookup only: the encrypted contents are NOT printed
    print("Found Grant ID", rec["id"], "| hash", label(hash_ok), "| signature", label(sig_ok))


def reviewer_hexdump():
    rec = find_record(ask_text("Grant ID to decrypt: "))
    if rec is None:
        print("Not found.")
        return
    hash_ok, sig_ok = check_record(rec)
    if not (hash_ok and sig_ok):
        print("Record is TAMPERED -- refusing to decrypt.")
        return
    desc = dec_text(rec["enc_desc"])
    print("Decrypted description (hex dump):")
    print(hexdump(desc))


# ----- finance officer -----

def officer_total():
    ids = ask_ids("Grant IDs to total (e.g. 1,3,4 or all): ")
    chosen = []
    for rec_id in ids:
        rec = find_record(rec_id)
        if rec is None:
            print("ID", rec_id, ": not found, skipped")
            continue
        hash_ok, sig_ok = check_record(rec)
        if hash_ok and sig_ok:
            print("ID", rec_id, ": verified")
            chosen.append(rec["enc_amt"])
        else:
            print("ID", rec_id, ": TAMPERED, skipped")

    if not chosen:
        print("Nothing to total.")
        return
    total = add_encrypted(chosen)
    print("Encrypted total:", short(str(total), 40))
    print("Decrypted total of", len(chosen), "grant(s):", dec_total(total))


# ----- demo helper: lets you SHOW tamper detection -----

def tamper_record():
    rec_id = ask_text("Grant ID to tamper with: ")
    records = load_records()
    for rec in records:
        if rec["id"] == rec_id:
            c = rec["enc_amt"]
            rec["enc_amt"] = c[:-1] + ("1" if c[-1] != "1" else "2")
            save_records(records)
            print("Changed one digit of the stored amount ciphertext.")
            return
    print("Not found.")


def main():
    global K
    K = load_or_create_keys()
    while True:
        print("\n===== SECURE GRANT EXPENSE PORTAL =====")
        print("1. Researcher")
        print("2. Reviewer")
        print("3. Finance Officer")
        print("4. (demo) Tamper with a record")
        print("5. Exit")
        choice = input("Role: ").strip()

        if choice == "1":
            run_menu("Researcher", [
                ("Submit grant", researcher_submit),
                ("View all records", view_all),
            ])
        elif choice == "2":
            run_menu("Reviewer", [
                ("Verify all records (signature + MD5)", reviewer_verify),
                ("Search by Grant ID", reviewer_search),
                ("Decrypt description as hex dump", reviewer_hexdump),
                ("View all records", view_all),
            ])
        elif choice == "3":
            run_menu("Finance Officer", [
                ("Total selected grants (homomorphic)", officer_total),
            ])
        elif choice == "4":
            safe(tamper_record)()
        elif choice == "5":
            print("Bye.")
            break
        else:
            print("Invalid choice.")


# ---------- self-test: python portal_template.py test ----------

def self_test():
    import builtins
    import tempfile
    global K, RECORDS_FILE, KEYS_FILE

    tmp = tempfile.mkdtemp()
    RECORDS_FILE = os.path.join(tmp, "records.txt")
    KEYS_FILE = os.path.join(tmp, "keys.txt")
    K = load_or_create_keys()

    # fake keyboard: each input() call prints the prompt + the next answer
    queue = []
    builtins.input = lambda prompt="": (print(prompt, end="") or True) and (print(queue[0]) or queue.pop(0))

    def run(fn, *answers):
        queue[:] = list(answers)
        safe(fn)()

    run(researcher_submit, "G1", "Lab equipment", "5000")
    run(researcher_submit, "G2", "Travel", "1200")
    run(researcher_submit, "G3", "Conference fee", "800")
    run(researcher_submit, "G1")                         # duplicate ID
    run(researcher_submit, "G4", "Bad amount", "abc", "-5", "300")   # invalid input

    K = load_or_create_keys()                            # simulate restart
    assert len(load_records()) == 4

    run(reviewer_verify)
    run(reviewer_search, "G2")
    run(reviewer_search, "G9")
    run(reviewer_hexdump, "G1")

    run(officer_total, "G1,G3")
    assert dec_total(add_encrypted([find_record(i)["enc_amt"] for i in ["G1", "G3"]])) == 5800

    run(tamper_record, "G3")
    assert check_record(find_record("G3")) == (False, True)
    run(reviewer_verify)
    run(officer_total, "all")
    run(reviewer_hexdump, "G3")

    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        self_test()
    else:
        main()
