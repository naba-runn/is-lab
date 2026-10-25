# SecureVault -- exam TEMPLATE
#
# QUESTION
#   Roles: Client, Lawyer, Compliance Officer.
#   Client            : encrypt a legal document with DES-CBC (with IV), compute
#                       SHA-256 of the ciphertext, ElGamal-sign it, add a
#                       timestamp; display everything and store it in a file.
#   Lawyer            : verify hash and signature; decrypt ONLY if both pass;
#                       store the access status with a timestamp.
#   Compliance Officer: verify only (never decrypt) and write a compliance report.
#
# HOW TO ADAPT -- search for "CHANGE:"
#   - file names, the record fields, the role names in main()
#   - the DES key (random here; a typed key is one line)
#   - other cipher? replace des_cbc_encrypt / des_cbc_decrypt; other signature?
#     replace sign_hash / verify_hash (every *_sign / *_verify has the same shape)
#
# Run:  python securevault.py         (menu)
#       python securevault.py test    (runs every action with typed-in answers)

import hashlib
import os
import sys
from datetime import datetime
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, getRandomRange


# ---- from ciphers/block_modes.py (verbatim) ----

ALGORITHMS = {"aes": AES, "des": DES}


PADDED_MODES = ("ecb", "cbc")            # CFB, OFB, CTR need no padding


def _to_bytes(value):
    return value.encode() if isinstance(value, str) else value


def _new_cipher(algorithm, mode, key, iv):
    module = ALGORITHMS[algorithm]
    mode_constant = getattr(module, "MODE_" + mode.upper())

    if mode == "ecb":
        return module.new(key, mode_constant)
    if mode == "ctr":
        return module.new(key, mode_constant, nonce=iv)
    return module.new(key, mode_constant, iv)


def block_encrypt(algorithm, mode, key, plaintext, iv=None):
    algorithm, mode = algorithm.lower(), mode.lower()
    module = ALGORITHMS[algorithm]
    data = plaintext.encode()

    if mode == "ecb":
        iv = b""
    else:
        iv_size = module.block_size // 2 if mode == "ctr" else module.block_size
        iv = _to_bytes(iv) if iv is not None else get_random_bytes(iv_size)
        if len(iv) != iv_size:
            raise ValueError(f"{algorithm} {mode}: iv/nonce must be {iv_size} bytes, got {len(iv)}")

    cipher = _new_cipher(algorithm, mode, _to_bytes(key), iv)
    if mode in PADDED_MODES:
        data = pad(data, module.block_size)

    return (iv + cipher.encrypt(data)).hex()


def block_decrypt(algorithm, mode, key, ciphertext):
    algorithm, mode = algorithm.lower(), mode.lower()
    module = ALGORITHMS[algorithm]
    raw = bytes.fromhex(ciphertext)

    if mode == "ecb":
        iv, encrypted = b"", raw
    else:
        iv_size = module.block_size // 2 if mode == "ctr" else module.block_size
        iv, encrypted = raw[:iv_size], raw[iv_size:]

    cipher = _new_cipher(algorithm, mode, _to_bytes(key), iv)   # a fresh cipher object
    data = cipher.decrypt(encrypted)
    if mode in PADDED_MODES:
        data = unpad(data, module.block_size)

    return data.decode()


# ---- from ciphers/elgamal_signature.py (verbatim) ----

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

    return str(r) + "," + str(s)


def elgamal_verify(message, signature, p, g, y):
    r, s = _split_signature(signature)
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


def _split_signature(signature):
    """A signature is the string "a,b"; numbers or a tuple (e.g. read from a file) work too."""
    if isinstance(signature, str):
        first, second = signature.split(",")
        return int(first), int(second)
    return int(signature[0]), int(signature[1])


# ---- from ciphers/hashing.py + ciphers/glue_snippets.py (verbatim) ----

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ==================== CHANGE: settings ====================

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS_FILE = os.path.join(HERE, "vault_records.txt")         # CHANGE: file names
ACCESS_FILE = os.path.join(HERE, "vault_access_log.txt")
REPORT_FILE = os.path.join(HERE, "vault_compliance_report.txt")

# one record per line: case_id|ciphertext|hash|signature|time
FIELDS = ["case_id", "ciphertext", "hash", "signature", "time"]   # CHANGE: add fields here AND in client_store

K = {}       # every key, filled ONCE by setup_keys()


def setup_keys():
    K["des"] = get_random_bytes(8)       # CHANGE: typed key -> input("DES key (8 chars): ").encode()[:8].ljust(8, b"\0")
    K["p"], K["g"], K["y"], K["x"] = elgamal_generate_keys()
    show("DES key (hex)", K["des"].hex())
    show("ElGamal public key (p, g, y)", (K["p"], K["g"], K["y"]))


# ==================== crypto in one place (CHANGE: swap algorithms here) ====================

def des_cbc_encrypt(plaintext):
    iv = get_random_bytes(8)                                    # fresh IV per document
    return block_encrypt("des", "cbc", K["des"], plaintext, iv)     # hex: IV (16 hex chars) + ciphertext


def des_cbc_decrypt(ciphertext):
    return block_decrypt("des", "cbc", K["des"], ciphertext)


def sign_hash(record_hash):
    return elgamal_sign(record_hash, K["p"], K["g"], K["x"])           # -> "r,s" string


def verify_hash(record_hash, signature):
    return elgamal_verify(record_hash, signature, K["p"], K["g"], K["y"])  # -> True / False


def check(rec):
    """(hash_ok, signature_ok) without decrypting anything."""
    hash_ok = sha256_hash(rec["ciphertext"]) == rec["hash"]
    try:
        sig_ok = verify_hash(rec["hash"], rec["signature"])
    except Exception:
        sig_ok = False
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


def find(case_id):
    return next((r for r in load_records() if r["case_id"] == case_id), None)


def append_line(path, text):
    with open(path, "a", encoding="utf-8") as f:
        f.write(text + "\n")


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

def client_store():
    case_id = ask_text("Case ID: ")
    if find(case_id):
        print("Case ID already exists.")
        return None
    document = ask_text("Legal document text: ")           # CHANGE: read a .txt file instead if asked

    section("client: encrypting " + case_id)
    ciphertext = des_cbc_encrypt(document)
    rec = {"case_id": case_id, "ciphertext": ciphertext}
    rec["hash"] = sha256_hash(ciphertext)
    rec["signature"] = sign_hash(rec["hash"])
    rec["time"] = timestamp()
    show("IV (hex)", ciphertext[:16])
    show("DES-CBC ciphertext (hex)", ciphertext)
    show("SHA-256 of ciphertext", rec["hash"])
    show("ElGamal signature (r,s)", rec["signature"])
    show("timestamp", rec["time"])

    append_line(RECORDS_FILE, "|".join(rec[k] for k in FIELDS))
    print("  stored in", RECORDS_FILE)
    return rec


def client_view():
    for rec in load_records():
        section("case " + rec["case_id"])
        for k in FIELDS:
            show(k, rec[k])


def lawyer_access():
    case_id = ask_text("Case ID to open: ")
    rec = find(case_id)
    if rec is None:
        print("Not found.")
        return None
    section("lawyer: verifying " + case_id)
    hash_ok, sig_ok = check(rec)
    show("hash stored", rec["hash"])
    show("hash recomputed", sha256_hash(rec["ciphertext"]))
    show("integrity", ok(hash_ok))
    show("signature", ok(sig_ok))
    if hash_ok and sig_ok:
        document = des_cbc_decrypt(rec["ciphertext"])        # decrypt ONLY after both checks
        section("decrypted document")
        print("    " + document)
        status = "GRANTED"
    else:
        print("  Verification failed -- document NOT decrypted.")
        document, status = None, "DENIED"
    append_line(ACCESS_FILE, timestamp() + "|Lawyer|" + case_id + "|" + status)
    show("access status", status + " (saved in " + os.path.basename(ACCESS_FILE) + ")")
    return document


def compliance_report():
    records = load_records()
    lines = ["COMPLIANCE REPORT " + timestamp(), ""]
    valid = 0
    for rec in records:
        hash_ok, sig_ok = check(rec)                         # verify only -- never decrypts
        status = "VALID" if hash_ok and sig_ok else "INVALID"
        valid += status == "VALID"
        lines.append(rec["case_id"] + " | " + rec["time"] + " | hash " + ok(hash_ok)
                     + " | signature " + ok(sig_ok) + " | " + status)
    lines += ["", "valid: " + str(valid) + " / " + str(len(records))]
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    section("compliance report")
    print("\n".join("  " + line for line in lines))
    print("  saved in", REPORT_FILE)
    return valid


def tamper():
    case_id = ask_text("Case ID to tamper with: ")
    records = load_records()
    for rec in records:
        if rec["case_id"] == case_id:
            c = rec["ciphertext"]
            rec["ciphertext"] = c[:-1] + ("0" if c[-1] != "0" else "1")
            save_records(records)
            print("Changed one character of the stored ciphertext.")
            return
    print("Not found.")


def main():
    setup_keys()
    for path in (RECORDS_FILE, ACCESS_FILE):     # new keys each run -> start with empty files
        if os.path.exists(path):
            os.remove(path)
    while True:
        print("\n===== SECUREVAULT =====")
        print("1. Client\n2. Lawyer\n3. Compliance Officer\n4. (demo) Tamper\n5. Exit")   # CHANGE: role names
        choice = input("Role: ").strip()
        if choice == "1":
            run_menu("Client", [("Encrypt, hash, sign and store a document", client_store),
                                ("View stored records", client_view)])
        elif choice == "2":
            run_menu("Lawyer", [("Verify and open a document", lawyer_access)])
        elif choice == "3":
            run_menu("Compliance Officer", [("Verify all + compliance report", compliance_report)])
        elif choice == "4":
            tamper()
        elif choice == "5":
            break


# ---------- self-test: python securevault.py test ----------

def self_test():
    import builtins
    import tempfile
    global RECORDS_FILE, ACCESS_FILE, REPORT_FILE
    tmp = tempfile.mkdtemp()
    RECORDS_FILE, ACCESS_FILE, REPORT_FILE = (os.path.join(tmp, n) for n in ("r.txt", "a.txt", "c.txt"))
    queue = []
    builtins.input = lambda prompt="": (print(prompt + queue[0]) or queue.pop(0))

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()

    setup_keys()
    run(client_store, "C1", "Contract between A and B")
    run(client_store, "C2", "Will of Mr X")
    run(client_view)
    assert run(lawyer_access, "C1") == "Contract between A and B"
    assert run(compliance_report) == 2
    run(tamper, "C2")
    assert run(lawyer_access, "C2") is None                 # tampered -> not decrypted
    assert run(compliance_report) == 1
    assert open(ACCESS_FILE).read().count("DENIED") == 1
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
