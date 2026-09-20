# Store a record so that its INTEGRITY (hash) and AUTHENTICITY (signature) can
# be checked later -- and check it WITHOUT decrypting, for roles that must
# never see the plaintext (Nurse, Admin, Auditor).
#
#   store_record  : encrypt -> hash the CIPHERTEXT -> sign the hash
#   verify_record : recompute the hash, verify the signature. Never decrypts.
#   read_record   : verify_record first, decrypt ONLY if both checks pass
#
# The cipher is passed in as a function, so any of them works:
#   RSA :  encrypt_fn=lambda t: rsa_encrypt(public_key, t)
#   AES :  encrypt_fn=lambda t: aes_encrypt(key, t, iv=iv)

import hashlib
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
    signature = pow(m, d, n)

    return signature


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


def tamper_hex(ciphertext_hex):
    """Flips the last hex character to simulate corruption/tampering of a
    hex-string ciphertext -- what ciphers/aes.py, rsa.py, tripledes.py etc.
    all return. Use this for "show integrity check fails" requirements."""
    last = ciphertext_hex[-1]
    flipped = "0" if last != "0" else "1"

    return ciphertext_hex[:-1] + flipped


# ---------- the pattern ----------

def store_record(plaintext, encrypt_fn, sign_fn):
    encrypted = encrypt_fn(plaintext)
    record_hash = sha256_hash(encrypted)

    return {
        "encrypted": encrypted,
        "hash": record_hash,
        "signature": sign_fn(record_hash),
        "timestamp": timestamp(),
    }


def verify_record(record, verify_fn):
    """Checks only; returns (integrity_ok, authentic_ok)."""
    integrity_ok = sha256_hash(record["encrypted"]) == record["hash"]
    authentic_ok = verify_fn(record["signature"]) == record["hash"]

    return integrity_ok, authentic_ok


def read_record(record, decrypt_fn, verify_fn):
    """The decrypted text, or None if either check fails."""
    integrity_ok, authentic_ok = verify_record(record, verify_fn)
    if not (integrity_ok and authentic_ok):
        return None

    return decrypt_fn(record["encrypted"])


def label(ok, yes="PASSED", no="FAILED"):
    """label(ok, "VALID", "INVALID") when the question wants those words."""
    return yes if ok else no


if __name__ == "__main__":
    private_key, public_key, n, e, d = rsa_generate_keys()

    encrypt_fn = lambda text: rsa_encrypt(public_key, text)
    decrypt_fn = lambda text: rsa_decrypt(private_key, text)
    sign_fn = lambda text: rsa_sign(text, d, n)
    verify_fn = lambda signature: rsa_verify(signature, e, n)

    record = store_record("Alice|34|F|O+|Hypertension", encrypt_fn, sign_fn)
    print("stored at        :", record["timestamp"])

    integrity_ok, authentic_ok = verify_record(record, verify_fn)      # what a Nurse / Admin does
    print("nurse integrity  :", label(integrity_ok))
    print("admin signature  :", label(authentic_ok, "VALID", "INVALID"))
    print("doctor reads     :", read_record(record, decrypt_fn, verify_fn))

    record["encrypted"] = tamper_hex(record["encrypted"])              # tamper demo
    integrity_ok, authentic_ok = verify_record(record, verify_fn)
    print("\nafter tampering  : integrity", label(integrity_ok), "| signature", label(authentic_ok, "VALID", "INVALID"))
    print("doctor reads     :", read_record(record, decrypt_fn, verify_fn))
