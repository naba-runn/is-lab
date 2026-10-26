# =============================================================================
# PRACTICE QUESTION (from guide/practice_questions.py)
#
# Q14 KeyVault -- key management service                         (labs 3, 4)
#  Hospitals register; the KMS generates an RSA (or Rabin) key pair per
#  hospital, stores it, lets an admin revoke or renew a key, and logs every
#  operation. Records encrypted with a revoked key must be refused.
#
# Hand-written template (key revoke / renew / expiry is not a generator option).
# Run:  python q14_keyvault.py      python q14_keyvault.py test
# =============================================================================

import os
import sys
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ---------- from ciphers/rsa.py (verbatim) ----------

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


# ---------- from ciphers/glue_snippets.py (verbatim) ----------

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ==================== CHANGE: settings ====================

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(HERE, "keyvault_keys.txt")          # entity|version|status|created|expires|private key
RECORDS_FILE = os.path.join(HERE, "keyvault_records.txt")    # record_id|entity|version|ciphertext|time
AUDIT_FILE = os.path.join(HERE, "keyvault_audit.txt")
KEY_LIFETIME_DAYS = 365                                      # CHANGE: key expiry
ENTITY = "Hospital"                                          # CHANGE: who owns keys (Hospital, Branch, ...)


# ---------- input / output helpers ----------

def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s:
            return s
        print("Please type something.")


def section(title):
    print("\n  " + title.upper() + "\n  " + "-" * len(title))


def show(name, value, width=24):
    text = str(value)
    lines = [text[i:i + 64] for i in range(0, len(text), 64)] or [""]
    print("  " + name.ljust(width) + " : " + ("\n" + " " * (width + 5)).join(lines))


def run_menu(title, options):
    while True:
        print("\n--- " + title + " ---")
        for i, (text, _) in enumerate(options, 1):
            print(str(i) + ". " + text)
        print(str(len(options) + 1) + ". Exit")
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


# ---------- the key store (one line per key version) ----------
# status: active (encrypts + decrypts) | retired (replaced by renew; still decrypts old records)
#         | revoked (nothing: records made with it are refused)

KEYS = []


def save_keys():
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        for k in KEYS:
            pem = k["private"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()).hex()
            f.write("|".join([k["entity"], str(k["version"]), k["status"], k["created"], k["expires"], pem]) + "\n")


def load_keys():
    KEYS.clear()
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, encoding="utf-8") as f:
            for line in f:
                entity, version, status, created, expires, pem = line.rstrip("\n").split("|")
                private = serialization.load_pem_private_key(bytes.fromhex(pem), password=None)
                KEYS.append({"entity": entity, "version": int(version), "status": status, "created": created,
                             "expires": expires, "private": private, "public": private.public_key()})


def audit(action, entity, detail):
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(timestamp() + "|" + action + "|" + entity + "|" + detail + "\n")
    show("audit", action + " " + entity + " " + detail)


def keys_of(entity):
    return [k for k in KEYS if k["entity"] == entity]


def active_key(entity):
    return next((k for k in keys_of(entity) if k["status"] == "active"), None)


def new_key(entity, version):
    private, public, n, e, d = rsa_generate_keys()
    now = datetime.now()
    key = {"entity": entity, "version": version, "status": "active", "created": now.strftime("%Y-%m-%d %H:%M"),
           "expires": (now + timedelta(days=KEY_LIFETIME_DAYS)).strftime("%Y-%m-%d %H:%M"),
           "private": private, "public": public}
    KEYS.append(key)
    save_keys()
    show("new RSA key pair", entity + " v" + str(version) + " (n has " + str(n.bit_length()) + " bits)")
    show("expires", key["expires"])
    return key


# ---------- actions ----------

def register():
    entity = ask_text(ENTITY + " name: ")
    if keys_of(entity):
        print(" ", entity, "is already registered.")
        return None
    key = new_key(entity, 1)
    audit("register", entity, "v1")
    return key


def encrypt_record():
    entity = ask_text(ENTITY + ": ")
    key = active_key(entity)
    if key is None:
        print("  REFUSED: no active key for", entity, "(revoked or not registered).")
        audit("encrypt", entity, "REFUSED no active key")
        return None
    if datetime.now().strftime("%Y-%m-%d %H:%M") > key["expires"]:
        print("  REFUSED: the key expired on", key["expires"], "-- renew it first.")
        audit("encrypt", entity, "REFUSED expired")
        return None
    rec_id = ask_text("Record ID: ")
    text = ask_text("Record text (short -- RSA-OAEP): ")
    ciphertext = rsa_encrypt(key["public"], text)
    with open(RECORDS_FILE, "a", encoding="utf-8") as f:
        f.write("|".join([rec_id, entity, str(key["version"]), ciphertext, timestamp()]) + "\n")
    show("encrypted with", entity + " key v" + str(key["version"]))
    show("ciphertext", ciphertext)
    audit("encrypt", entity, rec_id + " with v" + str(key["version"]))
    return rec_id


def find_record(rec_id):
    if os.path.exists(RECORDS_FILE):
        with open(RECORDS_FILE, encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("|")
                if parts[0] == rec_id:
                    return dict(zip(["id", "entity", "version", "ciphertext", "time"], parts))
    return None


def decrypt_record():
    rec = find_record(ask_text("Record ID: "))
    if rec is None:
        print("  Not found.")
        return None
    key = next((k for k in keys_of(rec["entity"]) if k["version"] == int(rec["version"])), None)
    show("made with", rec["entity"] + " key v" + rec["version"] + " (" + (key["status"] if key else "unknown") + ")")
    if key is None or key["status"] == "revoked":
        print("  REFUSED: that key was revoked -- the record cannot be opened.")
        audit("decrypt", rec["entity"], rec["id"] + " REFUSED revoked key")
        return None
    text = rsa_decrypt(key["private"], rec["ciphertext"])         # only after the key check
    show("decrypted", text)
    audit("decrypt", rec["entity"], rec["id"] + " OK")
    return text


def revoke():
    entity = ask_text(ENTITY + " whose active key is revoked: ")
    key = active_key(entity)
    if key is None:
        print("  No active key.")
        return None
    key["status"] = "revoked"
    save_keys()
    audit("revoke", entity, "v" + str(key["version"]))
    return key["version"]


def renew():
    entity = ask_text(ENTITY + " to renew: ")
    if not keys_of(entity):
        print("  Not registered.")
        return None
    old = active_key(entity)
    if old is not None:
        old["status"] = "retired"                   # still opens the records it made
    key = new_key(entity, max(k["version"] for k in keys_of(entity)) + 1)
    audit("renew", entity, "v" + str(key["version"]) + (" (v" + str(old["version"]) + " retired)" if old else ""))
    return key["version"]


def list_keys():
    section("key store")
    for k in KEYS:
        print("  " + k["entity"].ljust(12) + ("v" + str(k["version"])).ljust(5) + k["status"].ljust(9)
              + "created " + k["created"] + "  expires " + k["expires"])


def main():
    load_keys()
    run_menu("KeyVault (" + ENTITY + " keys)", [
        ("Register " + ENTITY + " (new RSA key pair)", register),
        ("Encrypt a record with its active key", encrypt_record),
        ("Decrypt a record (refused if its key was revoked)", decrypt_record),
        ("Revoke a key", revoke),
        ("Renew a key (old one retired)", renew),
        ("List keys", list_keys),
    ])


def self_test():
    import builtins
    import tempfile
    global KEYS_FILE, RECORDS_FILE, AUDIT_FILE
    tmp = tempfile.mkdtemp()
    KEYS_FILE, RECORDS_FILE, AUDIT_FILE = (os.path.join(tmp, n) for n in ("k.txt", "r.txt", "a.txt"))
    queue = []

    def fake_input(prompt=""):
        answer = queue.pop(0)
        print(prompt + answer)
        return answer

    builtins.input = fake_input

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()
    run(register, "CityHospital")
    assert run(register, "CityHospital") is None                     # already registered
    run(encrypt_record, "CityHospital", "R1", "Asha: BP 120/80")
    assert run(decrypt_record, "R1") == "Asha: BP 120/80"
    assert run(renew, "CityHospital") == 2
    load_keys()                                                      # restart: keys come back from the file
    assert run(decrypt_record, "R1") == "Asha: BP 120/80"            # retired v1 still opens old records
    run(encrypt_record, "CityHospital", "R2", "Ravi: sugar 140")     # made with v2
    assert run(revoke, "CityHospital") == 2
    assert run(decrypt_record, "R2") is None                         # revoked key -> refused
    assert run(encrypt_record, "CityHospital") is None               # no active key any more
    run(renew, "CityHospital")
    KEYS[-1]["expires"] = "2000-01-01 00:00"                         # pretend the new key expired
    assert run(encrypt_record, "CityHospital") is None
    run(list_keys)
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
