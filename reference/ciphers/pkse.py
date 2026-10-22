# Public-Key Searchable Encryption (PKSE) built on Paillier.
#
#   Anyone with the PUBLIC key can add to the index or send a query; only the
#   PRIVATE-key holder can read the results.
#
# The catch: Paillier is randomized, so Enc(word) never equals Enc(word) a second
# time -- you cannot look a query up in a dictionary of ciphertexts (the manual's
# sample would never find a match for the same reason). Instead the server tests
# equality HOMOMORPHICALLY, without the private key:
#
#   for every index entry:   Enc(entry_word) / Enc(query)  =  Enc(entry_word - query)
#                            raise it to a random r        =  Enc((entry_word - query) * r)
#   decrypt it:  0 -> the words are equal;   anything else -> random-looking noise
#
# So a query costs one homomorphic step per index entry on the server, plus one
# private-key decryption per entry on the client -- far slower than SSE's single
# dictionary lookup, but no shared secret is needed (public-key flexibility).
#
# Index: a list of (Enc(hash of word), [Enc(doc id as a number), ...]).
# All Paillier values are ints. The demo uses a 512-bit n for speed.

import sys
import time
import math
import hashlib
import string
from Crypto.Util.number import getPrime, getRandomRange


# ---- from ciphers/paillier.py (verbatim) ----

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


# ---------- the searchable-encryption part ----------

def _words(text):
    """Lower-case, punctuation stripped, each word once."""
    return set(word.strip(string.punctuation) for word in text.lower().split()) - {""}


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


if __name__ == "__main__":
    queries = sys.argv[1:] or ["patient", "encryption", "blood", "unicorn"]

    n, g, lam, mu = paillier_generate_keys(512)

    start = time.perf_counter()
    encrypted_index = pkse_create_index(DOCUMENTS, n, g)
    build_ms = (time.perf_counter() - start) * 1000

    print("documents :", len(DOCUMENTS))
    print("index     :", len(encrypted_index), "encrypted entries built in", f"{build_ms:.0f} ms")

    # why a plain lookup cannot work: the same word encrypts differently every time
    first_word_ciphertexts = {entry[0] for entry in encrypted_index}
    print("Enc('patient') found in the index by equality:",
          paillier_encrypt(n, g, _word_number("patient")) in first_word_ciphertexts)

    for query in queries:
        start = time.perf_counter()
        found = pkse_search(encrypted_index, query, n, g, lam, mu)
        search_ms = (time.perf_counter() - start) * 1000

        print(f"\nquery {query!r} -> {found}  ({search_ms:.0f} ms)")
        for doc_id in found:
            print("   ", doc_id, ":", DOCUMENTS[doc_id])
