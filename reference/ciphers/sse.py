# Symmetric Searchable Encryption (SSE): search an encrypted index without the
# server ever seeing a word or a document id.
#
#   index    word -> [document ids]                           (inverted index)
#   encrypt  the WORD becomes a keyed token (HMAC-SHA256)      -> can be looked up
#            the DOC IDS are AES-encrypted                     -> unreadable
#   search   token(query) -> look it up -> decrypt the returned ids
#
# Why the word is an HMAC and not AES: AES-CBC uses a random IV, so encrypting
# the same word twice gives two different ciphertexts and the query would never
# match the index. The token must be DETERMINISTIC (same word + same key ->
# same token) yet useless without the key -- exactly what HMAC gives.
#
# Trade-offs: search is one dictionary lookup (fast), but the server can see
# WHEN the same token is queried again (search pattern) and WHICH entries come
# back (access pattern). Needs a shared secret key (key distribution problem).
#
# The key is bytes (16 random bytes), not text.

import sys
import time
import hmac
import hashlib
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


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


# ---------- the searchable-encryption part ----------

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


if __name__ == "__main__":
    queries = sys.argv[1:] or ["patient", "encryption", "blood", "unicorn"]

    key = sse_generate_key()

    start = time.perf_counter()
    encrypted_index = sse_create_index(DOCUMENTS, key)
    build_ms = (time.perf_counter() - start) * 1000

    print("documents :", len(DOCUMENTS))
    print("index     :", len(encrypted_index), "encrypted entries built in", f"{build_ms:.1f} ms")
    token, encrypted_ids = next(iter(encrypted_index.items()))
    print("one entry :", token[:24] + "...", "->", [e[:16] + "..." for e in encrypted_ids])

    for query in queries:
        start = time.perf_counter()
        found = sse_search(encrypted_index, query, key)
        search_ms = (time.perf_counter() - start) * 1000

        print(f"\nquery {query!r} -> {found}  ({search_ms:.2f} ms)")
        for doc_id in found:
            print("   ", doc_id, ":", DOCUMENTS[doc_id])

    # the same query always makes the same token (the "search pattern" leak)
    print("\nsame token for the same query:", sse_trapdoor(key, "patient") == sse_trapdoor(key, "Patient"))
    # a different key cannot search this index at all
    print("a different key finds nothing:", sse_search(encrypted_index, "patient", sse_generate_key()) == [])
