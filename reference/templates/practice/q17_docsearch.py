# =============================================================================
# PRACTICE QUESTION (from guide/practice_questions.py)
#
# Q17 DocSearch -- encrypted document search                         (lab 8)
#  Ten text documents. Build an encrypted inverted index (word -> doc IDs)
#  with SSE and with PKSE, search for a word typed by the user, decrypt and
#  print the matching documents, and compare search times.
#
# Hand-written template (searches every WORD of each document).
# Run:  python q17_docsearch.py      python q17_docsearch.py test
# =============================================================================

import hashlib
import hmac
import math
import string
import sys
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, getRandomRange


# ---------- from ciphers/sse.py (verbatim) ----------

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


def _words(text):
    """Lower-case, punctuation stripped, each word once."""
    return set(word.strip(string.punctuation) for word in text.lower().split()) - {""}


def sse_generate_key():
    return get_random_bytes(16)


def sse_trapdoor(key, word):
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def sse_create_index(documents, key):
    index = {}
    for doc_id, text in documents.items():
        for word in _words(text):
            index.setdefault(sse_trapdoor(key, word), []).append(doc_id)

    return {token: [aes_encrypt(key, doc_id) for doc_id in doc_ids]
            for token, doc_ids in index.items()}


def sse_server_lookup(encrypted_index, token):
    """What the SERVER does: it only ever sees the token, never the key."""
    return encrypted_index.get(token, [])


def sse_search(encrypted_index, query, key):
    token = sse_trapdoor(key, query)                              # encrypt the query
    encrypted_ids = sse_server_lookup(encrypted_index, token)     # search the index
    return sorted(aes_decrypt(key, encrypted_id) for encrypted_id in encrypted_ids)


DOCUMENTS = {
    "doc1": "The patient record shows high blood pressure and needs follow up",
    "doc2": "Encrypted backups of the hospital database are stored offsite",
    "doc3": "The doctor reviewed the lab report and updated the patient record",
    "doc4": "Secure access to patient data requires a strong password and a key",
    "doc5": "The nurse recorded the blood pressure reading in the hospital system",
    "doc6": "A security audit found weak encryption in the legacy database",
    "doc7": "The auditor checked access logs for unauthorized access attempts",
    "doc8": "Doctors share the encrypted report using a secure channel",
    "doc9": "Key rotation keeps the encryption keys safe for every hospital",
    "doc10": "The lab uploaded a new report about blood tests for the patient",
}


# ---------- from ciphers/pkse.py (verbatim) ----------

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


def paillier_subtract(n, c1, c2):
    return (c1 * pow(c2, -1, n * n)) % (n * n)


def paillier_multiply_plain(n, ciphertext, k):
    return pow(ciphertext, k, n * n)


def _word_number(word):
    return int.from_bytes(hashlib.sha256(word.lower().encode()).digest(), "big")


def _text_to_number(text):
    return int.from_bytes(text.encode(), "big")


def _number_to_text(number):
    return number.to_bytes((number.bit_length() + 7) // 8, "big").decode()


def pkse_create_index(documents, n, g):
    index = {}
    for doc_id, text in documents.items():
        for word in _words(text):
            index.setdefault(word, []).append(doc_id)

    return [(paillier_encrypt(n, g, _word_number(word)),
             [paillier_encrypt(n, g, _text_to_number(doc_id)) for doc_id in doc_ids])
            for word, doc_ids in index.items()]


def pkse_encrypt_query(n, g, query):
    return paillier_encrypt(n, g, _word_number(query))


def pkse_server_search(encrypted_index, n, encrypted_query):
    """What the SERVER does: public key only, nothing it computes can be read."""
    results = []
    for encrypted_word, encrypted_ids in encrypted_index:
        difference = paillier_subtract(n, encrypted_word, encrypted_query)
        blinded = paillier_multiply_plain(n, difference, getRandomRange(1, 2 ** 64))
        results.append((blinded, encrypted_ids))

    return results


def pkse_open_results(n, lam, mu, results):
    """What the KEY HOLDER does: a decrypted 0 marks the matching entry."""
    found = []
    for blinded, encrypted_ids in results:
        if paillier_decrypt(n, lam, mu, blinded) == 0:
            found += [_number_to_text(paillier_decrypt(n, lam, mu, c)) for c in encrypted_ids]

    return sorted(found)


def pkse_search(encrypted_index, query, n, g, lam, mu):
    encrypted_query = pkse_encrypt_query(n, g, query)
    results = pkse_server_search(encrypted_index, n, encrypted_query)

    return pkse_open_results(n, lam, mu, results)


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


# ==================== the encrypted store (CHANGE: DOCUMENTS above = the question's documents) ====================

S = {}


def setup():
    section("building the encrypted store")
    S["doc_key"] = sse_generate_key()                                        # encrypts the documents
    S["docs"] = {d: aes_encrypt(S["doc_key"], text) for d, text in DOCUMENTS.items()}
    S["sse_key"] = sse_generate_key()
    start = time.perf_counter()
    S["sse"] = sse_create_index(DOCUMENTS, S["sse_key"])
    show("SSE index", "%d entries in %.1f ms" % (len(S["sse"]), (time.perf_counter() - start) * 1000))
    S["n"], S["g"], S["lam"], S["mu"] = paillier_generate_keys(512)
    start = time.perf_counter()
    S["pkse"] = pkse_create_index(DOCUMENTS, S["n"], S["g"])
    show("PKSE index", "%d entries in %.0f ms" % (len(S["pkse"]), (time.perf_counter() - start) * 1000))
    show("documents stored", "%d (AES-encrypted)" % len(S["docs"]))


def search(method, word):
    start = time.perf_counter()
    if method == "SSE":
        show("query token", sse_trapdoor(S["sse_key"], word))
        ids = sse_search(S["sse"], word, S["sse_key"])
    else:
        ids = pkse_search(S["pkse"], word, S["n"], S["g"], S["lam"], S["mu"])
    ms = (time.perf_counter() - start) * 1000
    section(method + " search for '" + word + "'")
    show("matching documents", ids if ids else "none")
    show("search time", "%.2f ms" % ms)
    for d in ids:
        print("    " + d + ": " + aes_decrypt(S["doc_key"], S["docs"][d]))     # decrypt the matches
    return ids


def compare(words=("patient", "encryption", "blood", "audit", "unicorn")):
    section("SSE vs PKSE")
    print("  %-12s %-28s %10s %10s" % ("word", "documents", "SSE ms", "PKSE ms"))
    for word in words:
        t0 = time.perf_counter(); a = sse_search(S["sse"], word, S["sse_key"]); t1 = time.perf_counter()
        b = pkse_search(S["pkse"], word, S["n"], S["g"], S["lam"], S["mu"]); t2 = time.perf_counter()
        print("  %-12s %-28s %10.2f %10.2f" % (word, ",".join(a) or "-", (t1 - t0) * 1000, (t2 - t1) * 1000))
        assert a == b
    print("  SSE: one dictionary lookup.  PKSE: one homomorphic test per index entry (no shared key needed).")


def main():
    setup()
    run_menu("DocSearch", [("Search with SSE", lambda: search("SSE", ask_text("Word: "))),
                           ("Search with PKSE", lambda: search("PKSE", ask_text("Word: "))),
                           ("Compare SSE and PKSE times", compare)])


def self_test():
    setup()
    plain = {}
    for d, text in DOCUMENTS.items():
        for w in _words(text):
            plain.setdefault(w, []).append(d)
    for word in ("patient", "blood", "encryption", "unicorn"):
        expected = sorted(plain.get(word, []))
        assert search("SSE", word) == expected and search("PKSE", word) == expected
    compare()
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
