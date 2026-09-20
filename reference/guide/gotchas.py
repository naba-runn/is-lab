# =============================================================================
#  GOTCHAS  --  the mistakes that cost time
# =============================================================================
#
#  TYPES
#   - Nearly every cipher file is string-in / string-out. Only
#     problems/file_transfer.py works on raw bytes.
#   - str.encode() -> bytes        bytes.decode() -> str
#     bytes.hex()  -> hex str      bytes.fromhex(s) -> bytes
#   - A big number read back from a text file is a STRING: int(...) it.
#
#  KEYS
#   - AES key must be 16 / 24 / 32 bytes. For a user-typed key of any length:
#         key = text.encode()[:16].ljust(16, b"\0")   (normalize_bytes)
#   - Key given as HEX -> bytes.fromhex(key), NOT key.encode(). Encoding the
#     hex string as ASCII gives the wrong bytes (a 32-char hex key silently
#     becomes AES-256).
#   - Triple DES with K1 = K2 = K3: pycryptodome's DES3 rejects it as a
#     degenerate key; ciphers/tripledes.py builds EDE from plain DES, so it
#     works.
#   - CTR nonce is HALF the block size (AES: 8 bytes, DES: 4 bytes).
#
#  RSA
#   - "Data too long for key size": RSA-2048 with OAEP holds about 190 bytes.
#     Use hybrid encryption (system_parts/hybrid_encryption.py); don't shorten
#     the message.
#   - A field containing "|" breaks records joined with "|".
#   - Encrypt with the PUBLIC key, decrypt with the PRIVATE key. Sign with the
#     PRIVATE key, verify with the PUBLIC key.
#
#  OTHER ALGORITHMS
#   - ElGamal / RSA with a small given prime or modulus: encrypt one character
#     at a time (each ASCII code must be < the modulus). ciphers/elgamal.py
#     and rsa_given_keys.py already do this.
#   - Rabin decryption gives 4 roots; ciphers/rabin.py keeps the one that is a
#     valid ASCII byte (< 256).
#   - "Signatures using Diffie-Hellman" means DSA (ciphers/dh_signature.py);
#     dh.py is only key exchange.
#
#  PYTHON
#   - Dict keys are strings: record["hash"], not record[hash].
#   - Menu choices from input() are strings: choice == "3", not choice == 3.
#     (system_parts/role_menu.py handles this for you.)
#   - Don't reuse a loop variable after the loop (r from "for r in records")
#     for something about ANOTHER record; use the record you selected.
#   - File mode "w" erases the file every time it's opened; "a" adds to it.
#     Reading a file that doesn't exist raises FileNotFoundError, which the
#     read functions in files/text_files.py already handle.
#   - A double quote inside a double-quoted f-string, f"{r["x"]}", is a
#     SyntaxError before Python 3.12. Use f"{r['x']}".
#   - pow(x, -1, m) is a modular inverse (Python 3.8+).
#   - Vigenere / Autokey "substring not found": the key or text has uppercase
#     or non-letters. The ciphers/ functions already lowercase and filter
#     their inputs; new code you write must too.
#
#  DEMOS
#   - RSA keys made when the program starts are gone when it stops. Records
#     saved to a file by an earlier run can no longer be verified or
#     decrypted. Clear the file at startup (files/text_files.py: clear_file),
#     or say in your answer that this is expected.
