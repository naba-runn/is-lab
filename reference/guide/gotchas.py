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
#   - AES key must be 16 / 24 / 32 bytes -- one dedicated file per size, all
#     with the same functions/structure, just a different key length:
#         AES-128 -> ciphers/aes128.py -> 32 hex chars (16 bytes)
#         AES-192 -> ciphers/aes192.py -> 48 hex chars (24 bytes)
#         AES-256 -> ciphers/aes256.py -> 64 hex chars (32 bytes)
#     (ciphers/aes.py is the generic string-key version -- any of 16/24/32
#     ASCII characters works, and pycryptodome picks the AES variant purely
#     from however many bytes the key turns out to be.)
#   - For a user-typed key of any length, force it to the size you need:
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
#
#  FILE PATHS
#   - A bare filename like "pat.txt" is a RELATIVE path: Python looks for it
#     next to wherever you LAUNCHED the interpreter from (the terminal's
#     current directory), not next to the .py file itself. Running
#     `python3 itb/pr.py` from one directory up looks for "itb/pat.txt" in
#     the wrong place and read_file returns "" (file "doesn't exist") even
#     though the file is right there next to the script.
#   - Symptom: IndexError on rec[0] / records[0] right after a read, with no
#     other explanation -- the list came back empty because the "file" the
#     program found was blank.
#   - PyCharm's Run button sets the working directory to the script's own
#     folder automatically, which is why this often only shows up when
#     running from a terminal instead. If you do use a terminal, `cd` into
#     the script's folder first.
#
#  PROGRAM STATE / LOOPS
#   - Don't call *_generate_keys() (or generate a fresh IV) inside the menu
#     loop that runs every time you return to the menu -- only at the very
#     start, once. Otherwise: sign a record as one role, switch to another
#     role, and by the time you verify it a NEW keypair has silently
#     replaced the old one. rsa_verify then checks the signature against
#     the WRONG (n, e), so it fails even though nothing else is wrong.
#     Symptom: authenticity_ok is always False, with no exception at all --
#     this one doesn't crash, it just silently gives the wrong answer.
#   - Generate once, in main(), before the menu loop starts, and pass the
#     same keys into every role's menu function for the rest of the run.
#     system_parts/key_management.py's KeyStore does this for you (keys are
#     created once per name and kept until you explicitly revoke/renew
#     them); system_parts/role_menu.py's run_menu() also naturally avoids
#     this because the loop it owns doesn't touch your keys at all.
#   - Same logic applies to a CBC/CFB/OFB IV: reusing ONE fixed IV for every
#     message you encrypt in a session is a real cryptographic weakness
#     (not just a style issue) -- generate a fresh IV per message, or pass
#     iv=None into aes_encrypt so it makes a fresh random one automatically.
#
#  RECORDS / FILES
#   - Only put plain text/numbers in a "|"-joined record field. A raw
#     bytes object (e.g. an IV) turned into a field with str(some_bytes)
#     stores its Python repr (b'...'), and any printable byte inside it --
#     including a literal "|" or "," -- becomes part of that repr and
#     SPLITS INTO EXTRA FIELDS when the record is read back, shifting every
#     later index (record[2], record[3], ...) off by one. Store bytes as
#     some_bytes.hex() instead (hex digits can never collide with a "|"
#     or "," delimiter), and bytes.fromhex(...) to get them back.
#   - A record's fields all come back as strings from read_records --
#     including one that started out as a big int (an RSA signature). Feed
#     that straight into pow(signature, e, n) without converting it back
#     first and you get:
#         TypeError: unsupported operand type(s) for ** or pow(): 'str', 'int', 'int'
#     Fix: signature = int(record[2]) before calling rsa_verify.
#
#  SECURITY ORDERING
#   - Decrypt AFTER checking integrity and authenticity, not before. Calling
#     aes_decrypt unconditionally and only deciding whether to PRINT the
#     result based on the checks still means you decrypted data you hadn't
#     verified yet -- do the checks first, and only call decrypt inside the
#     branch where both passed (see system_parts/integrity_and_signature.py).
#   - A line meant to run only on success/failure must be INSIDE that
#     if/else block (correctly indented under it), not after it. Code
#     placed after an if/else at the same indentation level as the `if`
#     always runs, regardless of which branch was taken -- e.g. a "verified
#     OK" log message that still gets written even when verification just
#     failed, because it wasn't actually inside the `if`.
#   - Copy-paste variable typos: recs[2] (the whole list, indexed) is not
#     the same thing as rec[2] (the ONE record you already selected). One
#     extra "s" either raises an IndexError on a short list, or silently
#     grabs a different record's field -- always double check plural vs.
#     singular after copying a line that indexes into a list.
#
#  APPEND-ONLY FILES ACROSS MULTIPLE RUNS
#   - append_line/append_record never erase what's already there, so if you
#     run the program more than once without clearing the file, it ends up
#     with one line per past run, not just the latest one.
#   - read_file/read_lines()/read_records() ALL return EVERYTHING in the
#     file, in order -- not "the current record". If you only want the most
#     recent entry, you must say so explicitly:
#         read_lines(path)[-1]      or      read_records(path)[-1]
#     Using plain read_file(path) here hands you every past run's ciphertext
#     concatenated into one string; bytes.fromhex(...) on that blob produces
#     something far longer than one real ciphertext, which shows up as
#     "ValueError: Ciphertext length must be equal to key size" (RSA) or
#     similarly wrong-length errors elsewhere -- not an obvious clue that
#     the real problem is "read the whole file instead of the last line".
#   - Related trailing-newline trap: append_line adds "\n" after every
#     entry; read_file keeps that "\n" (it returns the raw file contents),
#     but read_lines strips it. If you hash/compare a value with one
#     approach and read it back with the other, the strings differ by a
#     single trailing "\n" and every comparison silently fails -- e.g. an
#     integrity check reporting FAILED on a record that was never actually
#     tampered with. Use read_lines (or read_records), consistently, for
#     anything you also wrote with append_line/append_record.
#
#  MISSING return
#   - A function that computes something in a local variable but never
#     hits a `return` statement returns None -- no error, no warning.
#     Whatever you assign the result to becomes None, and the FIRST
#     failure usually shows up several lines later, somewhere that None
#     gets used as if it were real data (e.g. hashlib.sha256(None) ->
#     AttributeError: 'NoneType' object has no attribute ...). If a
#     function "runs fine" but everything downstream breaks, check that
#     every code path through it actually has a `return`.
#
#  TAMPER / CORRUPTION DEMOS
#   - Once you've flipped bits in a ciphertext (tamper_bytes, XOR-ing a
#     byte with 0xFF, etc.), the result is essentially always INVALID as
#     UTF-8 text -- flipping every bit of an ASCII byte pushes it into the
#     0x80-0xFF range, which isn't valid UTF-8 on its own. Calling
#     .decode() on tampered bytes raises UnicodeDecodeError; hashing them
#     needs a representation that works for ANY byte value:
#         hashlib.sha256(tampered_bytes).hexdigest()          -- raw bytes in
#         sha256_hash(tampered_bytes.hex())                   -- via the
#                                                                  string-only
#                                                                  helper
#     Use .hex(), never .decode(), to turn corrupted/tampered bytes into a
#     string for hashing, printing, or storing in a text file.
#
#  HOMOMORPHIC ENCRYPTION (lab 7)
#   - What each scheme can do (all in generate.py / ciphers/):
#       Paillier : add ciphertexts, + constant, x constant, subtract (NOT ct x ct)
#       RSA      : multiply ciphertexts, x constant (Enc(m)*k^e), ^ constant (NOT add)
#       ElGamal  : multiply ciphertexts, x constant (c2*k), ^ constant (NOT add)
#       exponential ElGamal (encrypt g^m): add ciphertexts -- small totals only,
#       decryption searches for m
#   - Paillier adds, textbook RSA multiplies -- neither does both. Enc(a)*Enc(b)
#     is the SUM under Paillier but the PRODUCT under textbook RSA, and adding
#     two RSA ciphertexts gives garbage.
#   - The ciphertexts are NOT hex strings, they are big ints. Through a text
#     file they come back as strings, so int(...) them (ciphers/paillier.py).
#   - RSA's multiplicative property exists only for UNPADDED (textbook) RSA.
#     ciphers/rsa.py uses OAEP, which deliberately destroys it -- use
#     ciphers/rsa_homomorphic.py for "multiply encrypted numbers".
#   - Keep every plaintext AND the result below the modulus n or the value wraps
#     around and decrypts to the wrong number.
#   - A negative Paillier result decrypts as n - |value|, a huge positive number.
#     Treat anything above n // 2 as negative (problems/secure_diagnosis.py).
#   - Comparing encrypted numbers (> / <): ElGamal only multiplies, so the manual's
#     ElGamal "comparison" is not a real one. With Paillier: subtract, blind with a
#     random multiplier, decrypt only the sign.
#
#  SEARCHABLE ENCRYPTION (lab 8)
#   - Randomized encryption cannot be used as a lookup key. AES-CBC with a random
#     IV, RSA-OAEP and Paillier give a different ciphertext every time, so a
#     dictionary keyed by Enc(word) never matches the query (this is why the
#     manual's sample code finds nothing). SSE uses a deterministic keyed token
#     (HMAC); PKSE tests equality homomorphically (ciphers/pkse.py).
#   - Hashing the word is not enough on its own: anyone can hash a guess and look
#     it up. The token must depend on a SECRET key (HMAC), never a bare SHA-256.
#   - Lowercase and strip punctuation before indexing AND before querying, or
#     "Patient," and "patient" become different words.
