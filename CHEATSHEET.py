# == IS LAB EXAM CHEAT SHEET ==============================================
#
# Everything real lives in reference/, split into two folders:
#
#   reference/ciphers/   one dedicated file per algorithm -- generate_key /
#                         encrypt / decrypt (or sign/verify) and nothing else.
#                         Every single cipher/signature/hashing algorithm in
#                         the whole lab has at least one file here, plus
#                         glue_snippets.py for the small non-cryptographic
#                         helpers (timestamps, key normalization, tamper
#                         simulation) that composite questions also need.
#
#   reference/problems/  composite files that DO something with those
#                         algorithms: timing comparisons, socket client/
#                         server pairs, multi-step systems (role-based
#                         access, key management services, hybrid file
#                         transfer). Every file in here is self-contained
#                         (no imports from ciphers/) so you can copy just
#                         that one file into your exam submission.
#
# This file is just an index plus the glue code composite questions always
# need but no single file contains on its own. Use PyCharm's "Search
# Everywhere" (double-Shift) or Ctrl+F in this file to jump around fast.
#
# This file is safe to open or even run by accident -- every code sample
# below sits inside "if False:" so it's real, fully syntax-highlighted
# Python, but none of it executes.


# == 0. HOW TO ASSEMBLE A SOLUTION DURING THE EXAM ==========================
#
# A 6-step process for turning a question into working code using only
# what's in ciphers/. Do these in order; don't skip straight to typing.
#
# STEP 1 -- Identify the algorithm(s) the question names.
#   Read the question once and list every algorithm keyword (AES, RSA,
#   ElGamal, SHA-256, Diffie-Hellman, digital signature, ...). Look each one
#   up in the INDEX (section 1 below) to get its exact ciphers/ filename.
#   A question combining 3 algorithms needs 3 ciphers/ files open, not one.
#
# STEP 2 -- Decide "given" vs "generate".
#   Does the question hand you numbers (a key, a modulus, p/g/h, an IV)?
#   -> use them directly, skip any *_generate_keys()/*_generate_key() call.
#   Does it say "generate a keypair" / doesn't give you numbers?
#   -> call the generate function first. See section 2 below for the
#   specific "given RSA numbers" / "given ElGamal params" / "given DH
#   params" traps -- using the wrong file here is the #1 time-waster.
#
# STEP 3 -- Copy the exact functions you need, verbatim, in this order:
#   generate_key (if needed) -> encrypt -> decrypt (-> sign/verify if asked).
#   Paste them near the top of your exam file, unchanged. Do not "clean up"
#   or shorten them while pasting -- that's how typos get introduced under
#   time pressure. Copy first, adapt after, if at all.
#
# STEP 4 -- Check the data type each function expects vs. what you have.
#   Read section 4 below (STRING VS BYTES). If your data is a plain message
#   or a key you'll type in, everything here is string-in/string-out and
#   needs zero adaptation. If your data is file content, use ciphers/aes.py
#   and ciphers/rsa.py in TEXT mode too when the file is text (see
#   hospital_management.py's approach) -- don't reach for a bytes-native
#   variant unless the data genuinely can't be decoded as text.
#   ciphers/aes.py's aes_encrypt(key, plaintext, iv=None) already accepts
#   either a string or raw bytes for `key`, and an optional given `iv` --
#   check there first before writing a new AES variant.
#
# STEP 5 -- Add the non-crypto glue, from ciphers/glue_snippets.py:
#   - normalize_bytes(text, length)  -- arbitrary user string -> exact-length
#     key/IV (16/24/32 bytes). Needed whenever a question says "with a key
#     provided by the user" but doesn't guarantee its length.
#   - timestamp()                    -- needed whenever a question asks you
#     to record/display/log when something happened.
#   - tamper_hex(ciphertext) / tamper_bytes(data) -- needed whenever a
#     question asks you to "demonstrate/show integrity failure" or
#     "simulate tampering/corruption".
#   For a role-based or menu-driven system, or an in-memory record store,
#   copy the skeletons in section 3 below (GLUE PATTERNS) instead -- those
#   are structural templates you fill in, not fixed functions.
#
# STEP 6 -- Wire it together in the same order the question lists its
#   steps, printing exactly what it asks you to display, and test after
#   EVERY new piece (run the file after adding encrypt, again after adding
#   the hash check, again after adding decrypt) rather than writing
#   everything and debugging once at the end -- it's faster to find a typo
#   in 5 lines you just added than in 80 lines you wrote ten minutes ago.
#
# ---- WORKED EXAMPLE ----
# Question: "Encrypt a message with AES using a key and IV the user types
# in. Hash the ciphertext. Sign the hash with RSA. Verify and decrypt only
# if both the hash and signature check out; otherwise show an error. Then
# show what happens if the ciphertext is tampered with."
#
#   1. Keywords: AES, SHA-256 hash, RSA signature, integrity/tamper demo.
#   2. AES key + IV are "given" (typed by the user, of arbitrary length) ->
#      need normalize_bytes. RSA keys aren't given -> generate them.
#   3. Copy verbatim: aes_encrypt/aes_decrypt from ciphers/aes.py,
#      rsa_generate_keys from ciphers/rsa.py, rsa_sign/rsa_verify from
#      ciphers/rsa_signature.py, sha256_hash from ciphers/hashing.py.
#   4. Message and key are user-typed text -> plain strings, zero
#      adaptation needed for any of the four functions above.
#   5. Copy normalize_bytes and tamper_hex from ciphers/glue_snippets.py.
#   6. Order: normalize key/iv -> aes_encrypt -> sha256_hash(ciphertext) ->
#      rsa_sign(that hash) -> [receiver side] recompute hash, compare;
#      rsa_verify(signature) and compare to the recomputed hash; if both
#      match, aes_decrypt and print it, else print an error -> finally
#      call tamper_hex on the ciphertext, recompute its hash, show the
#      comparison now fails.
#   This is exactly medisecure.py's Doctor-role logic -- see
#   problems/medisecure.py if you want to see the fully assembled result.


# == 1. INDEX: requirement -> file =========================================
#
# -- ciphers/ (single algorithm, nothing else) -----------------------------
#   Additive / multiplicative / affine cipher ......... ciphers/primitives.py
#   Vigenere cipher .................................... ciphers/vigenere.py
#   Autokey cipher ...................................... ciphers/autokey.py
#   Playfair cipher ..................................... ciphers/playfair.py
#   Hill cipher .......................................... ciphers/hill.py
#   DES .................................................. ciphers/des.py
#   Triple DES ........................................... ciphers/tripledes.py
#   AES (any key length, generic) ........................ ciphers/aes.py
#   AES-128 with a GIVEN hex key ......................... ciphers/aes128.py
#   AES-192 showing every round (key exp/rounds/final) ... ciphers/aes192_steps.py
#   RSA (generate real keys via `cryptography` lib) ...... ciphers/rsa.py
#   RSA with GIVEN raw n/e/d numbers ..................... ciphers/rsa_given_keys.py
#   RSA digital signature (matches the Alice/Bob lab) .... ciphers/rsa_signature.py
#   ElGamal encryption (works with given small p/g/h/x) .. ciphers/elgamal.py
#   ElGamal digital signature ............................ ciphers/elgamal_signature.py
#   Schnorr signature .................................... ciphers/schnorr_signature.py
#   Diffie-Hellman key exchange .......................... ciphers/dh.py
#   DSA (the actual "DH-based" signature scheme) ......... ciphers/dh_signature.py
#   ECC / ECIES encryption ............................... ciphers/ecc.py
#   Rabin cryptosystem ................................... ciphers/rabin.py
#   Custom hash function (djb2-style, 5381/33/mask) ...... ciphers/hash_function.py
#   MD5 / SHA-1 / SHA-256 (plain hashlib wrappers) ....... ciphers/hashing.py
#   Timestamps / key normalization / tamper simulation ... ciphers/glue_snippets.py
#
# -- problems/ (measurement, sockets, multi-step systems) -------------------
#   DES vs AES-256 timing comparison ..................... problems/des_vs_aes256.py
#   RSA vs ECC file-transfer benchmark (hybrid enc.) ..... problems/file_transfer.py
#   Enterprise RSA+DH comms + key mgmt + scalability ..... problems/secure_corp.py
#   Rabin-based centralized Key Management Service ....... problems/rabin_kms.py
#   MD5/SHA-1/SHA-256 timing + collision demo ............ problems/hash_comparison.py
#   Hash integrity over a socket (tamper detection) ...... problems/hash_server.py + hash_client.py
#   Digital signature over a socket ...................... problems/signature_server.py + signature_client.py
#   Role-based system (Patient/Doctor/Auditor, RBAC) ..... problems/medisecure.py
#   File-based hybrid system (AES+RSA+ElGamal+hash+tamper) problems/hospital_management.py
#   Chained cipher example (Vigenere -> AES -> RSA) ...... problems/prac1.py
#
# If the exam question is "similar but different" from one of these, open
# the closest matching file and edit the message/keys near the bottom --
# the function structure almost never needs to change, just the
# `if __name__ == "__main__":` block.


# == 1.5 EVERY problems/ FILE IS LITERALLY ASSEMBLED FROM ciphers/ FILES ====
#
# Every function that does actual encrypt/decrypt/sign/verify/hash work
# inside a problems/ file is a byte-for-byte copy of the matching function
# in ciphers/ (only the orchestration -- menus, sockets, file I/O, timing,
# print statements -- is new). This is deliberate: if your exam question
# looks like one of these, you can rebuild it by pasting the listed
# ciphers/ functions and writing only the glue between them.
#
#   des_vs_aes256.py       <- ciphers/des.py (verbatim) + ciphers/aes.py
#                              (verbatim; a 32-char key just makes it AES-256)
#   file_transfer.py       <- ciphers/rsa.py + ciphers/ecc.py + ciphers/aes.py,
#                              adapted for raw bytes (file data) instead of text
#   secure_corp.py         <- ciphers/rsa.py + ciphers/dh.py + ciphers/aes.py
#                              (all verbatim)
#   rabin_kms.py           <- ciphers/rabin.py (verbatim) + ciphers/aes.py
#                              (verbatim, used to seal private keys at rest)
#   hash_comparison.py     <- hashlib.new(algorithm, ...), the same recipe as
#                              ciphers/hashing.py's md5_hash/sha1_hash/sha256_hash
#   hash_server.py/client  <- ciphers/hash_function.py's custom_hash (verbatim,
#                              inlined so each file stays standalone)
#   signature_server/client<- ciphers/rsa_signature.py's rsa_sign/rsa_verify
#                              (verbatim, inlined so each file stays standalone)
#   medisecure.py          <- ciphers/aes.py (verbatim, using its iv=... param)
#                              + ciphers/rsa.py (verbatim) + ciphers/rsa_signature.py
#                              (verbatim -- it signs the hash's hex STRING
#                              directly, exactly like signing any other message)
#   hospital_management.py <- ciphers/aes.py + ciphers/rsa.py + ciphers/elgamal.py
#                              + ciphers/hashing.py, ALL verbatim (the file
#                              works in plain text/hex-string mode throughout
#                              specifically so every piece can be reused as-is)
#   prac1.py                <- ciphers/vigenere.py + ciphers/aes.py + ciphers/rsa.py
#                              (all verbatim)
#
# ciphers/aes.py's aes_encrypt(key, plaintext, iv=None) is the one function
# used the most across problems/: `key` accepts either a string or raw bytes,
# and `iv` can be a given value instead of a random one -- which is exactly
# what covers both "type a key" questions and "derived/given key or IV"
# questions without needing a second version of the function.


# == 2. "GIVEN PARAMETERS" VS "GENERATE YOUR OWN" ==========================
#
# Many questions hand you literal numbers instead of asking you to generate
# a keypair. Using the wrong file wastes time.
#
#   RSA, given (n, e, d)          -> rsa_given_keys.py
#       rsa.py will NOT work here -- it builds real `cryptography` key
#       OBJECTS, which reject tiny/toy moduli.
#
#   RSA, "generate a 2048-bit keypair"  -> rsa.py or rsa_signature.py
#
#   ElGamal, given (p, g, h, x)   -> call elgamal_encrypt/elgamal_decrypt
#       from elgamal.py directly, skip elgamal_generate_keys() entirely.
#       Already encrypts per-character, so it works even with a tiny demo
#       prime like p = 7919.
#
#   Diffie-Hellman, given (p, g)  -> skip dh_generate_parameters(), just
#       call dh_generate_keypair(p, g) for each side.


# == 3. GLUE PATTERNS (not tied to one file) ===============================

# ---- Hybrid encryption (RSA/ECC can't handle big data directly) ----------
# RSA-OAEP tops out around ~190 bytes for a 2048-bit key. For "encrypt this
# file" questions: AES encrypts the actual data, RSA/ECC only encrypts the
# 16-byte AES key. See file_transfer.py or hospital_management.py.
if False:
    aes_key = get_random_bytes(16)
    encrypted_data = aes_encrypt_bytes(aes_key, file_bytes)      # bulk data
    encrypted_key = rsa_encrypt_key(public_key, aes_key)         # tiny payload


# ---- Hash-based integrity check + tamper demo ----------------------------
# The recurring "verify, and show what happens if tampered" pattern.
# See hospital_management.py or hash_client.py.
if False:
    sender_hash = hashlib.sha256(data).hexdigest()
    # ... send data ...
    receiver_hash = hashlib.sha256(received_data).hexdigest()

    if sender_hash == receiver_hash:
        pass  # decrypt / trust it
    else:
        print("Integrity check FAILED")

    # to demonstrate a failure on purpose:
    tampered = bytearray(received_data)
    tampered[-1] ^= 0xFF   # flip one byte
    # for text/hex ciphertext instead of bytes, flip one character instead:
    # ciphertext[:-1] + ('0' if ciphertext[-1] != '0' else '1')


# ---- Role-based menu skeleton ---------------------------------------------
# Full pattern in medisecure.py. Minimal shape below. Enforce access control
# by STRUCTURE: a role's menu function simply never calls the decrypt/reveal
# function -- that alone satisfies "must not be able to decrypt" requirements.
if False:
    def role_a_menu():
        while True:
            print("1. Action\n2. Back")
            choice = input("Choice: ").strip()
            if choice == "1":
                pass
            elif choice == "2":
                break

    def main():
        while True:
            print("1. Role A\n2. Role B\n3. Exit")
            choice = input("Select role: ").strip()
            if choice == "1":
                role_a_menu()
            elif choice == "2":
                pass  # role_b_menu()
            elif choice == "3":
                break


# ---- Key management service skeleton -------------------------------------
# generate / distribute / revoke / renew / audit-log.
# Full pattern: rabin.py's RabinKeyManagementService, or secure_corp.py's
# KeyManager. Shape: a dict keyed by name/facility, an "active" flag for
# revocation, a "created_at" timestamp for renewal, and a running
# "audit_log" list that every operation appends to.


# ---- Socket server/client skeleton ----------------------------------------
if False:
    # server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 65432))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            data = conn.recv(4096)
            conn.sendall(response.encode())

    # client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 65432))
        s.sendall(message.encode())
        reply = s.recv(4096).decode()

# Run the server first (python3 hash_server.py &  to background it in the
# same terminal, or use a second terminal / a second PyCharm Run
# configuration), then run the client.


# ---- Timestamps and file I/O one-liners -----------------------------------
if False:
    from datetime import datetime
    datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "r") as f:
        text = f.read()          # text file in
    with open(path, "w") as f:
        f.write(text)            # text file out
    with open(path, "rb") as f:
        data = f.read()          # binary file in
    with open(path, "wb") as f:
        f.write(data)            # binary file out


# ---- Writing/reading MULTIPLE records in one file -------------------------
#
# The one-liners above overwrite the whole file every time -- fine for a
# single document, wrong for "store every patient record" where each new
# record must be ADDED without wiping out the earlier ones. Two ways to do
# that; pick whichever matches how complex each record is.
#
# Option A -- delimited text, one record per line (simplest; matches the
# "document|signature" style already used in signature_server.py):
if False:
    def append_record(filename, fields):
        with open(filename, "a") as f:                       # "a" = append
            f.write("|".join(str(field) for field in fields) + "\n")

    def read_all_records(filename):
        records = []
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line:                                       # skip blank lines
                    records.append(line.split("|"))
        return records

    # writing several patient records over time (e.g. once per Patient upload):
    append_record("records.txt", ["alice", encrypted_hex, hash_hex, timestamp()])
    append_record("records.txt", ["bob", encrypted_hex2, hash_hex2, timestamp()])

    # reading them all back later (e.g. for a Doctor/Auditor menu to list):
    for name, encrypted_hex, hash_hex, ts in read_all_records("records.txt"):
        print(name, ts)

    # finding one specific record by a field (e.g. by patient name):
    match = next((r for r in read_all_records("records.txt") if r[0] == "bob"), None)
#
# Option B -- JSON Lines, one JSON object per line (safer when a record has
# many named fields, or a field might itself contain "|"):
if False:
    import json

    def append_record_json(filename, record_dict):
        with open(filename, "a") as f:
            f.write(json.dumps(record_dict) + "\n")

    def read_all_records_json(filename):
        records = []
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    append_record_json("records.jsonl", {
        "name": "alice", "hash": hash_hex, "timestamp": timestamp(),
    })

    for record in read_all_records_json("records.jsonl"):
        print(record["name"], record["timestamp"])
#
# Both options were verified working. "a" mode is the key idea either way:
# "w" mode truncates the file back to empty every time you open it, so
# writing record #2 with "w" would silently destroy record #1 -- always use
# "a" when adding one record at a time to a file that should keep growing.


# ---- Multiple INPUT FIELDS (name, age, diagnosis, ...) -> one record ------
#
# When a record isn't a single block of text but several separate fields
# (name, age, diagnosis, ...), join them into ONE string first, then run
# that one string through the normal encrypt -> hash -> sign pipeline
# exactly like a whole file's content. Splitting back into fields on the
# way out is just the reverse join.
if False:
    def build_record(*fields):
        """Concatenate fields into one string with a delimiter, ready to
        encrypt. '|' is safe as long as no field value contains '|' itself."""
        return "|".join(str(field) for field in fields)

    def parse_record(record_string):
        """Reverse of build_record: splits back into the original fields."""
        return record_string.split("|")

    # ---- store: fields -> concatenated -> encrypted+hashed+signed ----
    def store_record(fields, aes_key, aes_iv, d, n):
        plaintext = build_record(*fields)                        # concatenate
        encrypted = aes_encrypt(aes_key, plaintext, iv=aes_iv)    # ciphers/aes.py
        record_hash = sha256_hex(encrypted)                       # ciphers/hashing.py
        signature = rsa_sign(record_hash, d, n)                   # ciphers/rsa_signature.py

        return {
            "encrypted": encrypted,
            "hash": record_hash,
            "signature": signature,
            "timestamp": timestamp(),
        }

    # ---- retrieve: verify, THEN decrypt, THEN split back into fields ----
    def retrieve_record(record, aes_key, aes_iv, e, n):
        integrity_ok = sha256_hex(record["encrypted"]) == record["hash"]
        authenticity_ok = rsa_verify(record["signature"], e, n) == record["hash"]

        if not (integrity_ok and authenticity_ok):
            return None                                            # refuse to decrypt

        plaintext = aes_decrypt(aes_key, record["encrypted"])
        return parse_record(plaintext)                             # back to a list of fields

    # usage:
    record = store_record(["Alice", 34, "Hypertension"], aes_key, aes_iv, d, n)
    # record == {"encrypted": "...", "hash": "...", "signature": ..., "timestamp": "..."}

    fields = retrieve_record(record, aes_key, aes_iv, e, n)
    # fields == ["Alice", "34", "Hypertension"]  (everything comes back as strings --
    # cast back with int(fields[1]) etc. if you need age as a number again)
#
# Verified end-to-end, including a tamper case: flipping one character of
# record["encrypted"] before calling retrieve_record correctly makes
# integrity_ok False and retrieve_record returns None instead of decrypting.
# This is the exact same shape as medisecure.py's Patient-upload /
# Doctor-decrypt pair -- store_record is what patient_menu()'s upload
# branch does, retrieve_record is what doctor_menu()'s decrypt branch does,
# just generalized to take a list of fields instead of a whole file's text.


# ---- Bundling encrypted text with WHATEVER else needs to travel with it ---
#
# More general than store_record/retrieve_record above: you already have
# the encrypted text (from whichever cipher the question uses) plus some
# other pieces computed separately -- a hash, a signature, an IV, a
# sender's name, whatever the question asks to be stored alongside it.
# This is just the packaging step: bundle them into one dict, then pull
# them back out by name later. No assumption about which cipher/hash/sign
# functions were used to produce the values in the first place.
if False:
    def make_record(encrypted_text, **extra_fields):
        record = {"encrypted": encrypted_text}
        record.update(extra_fields)
        return record

    # usage -- pass in any extra fields the question asks for, by name:
    record = make_record(
        encrypted_text,
        hash=hash_value,
        signature=signature_value,
        timestamp=timestamp(),
    )
    # record == {"encrypted": "...", "hash": "...", "signature": ..., "timestamp": "..."}

    # retrieve: just pull fields back out by key
    encrypted_text = record["encrypted"]
    hash_value = record["hash"]
    signature_value = record["signature"]
    ts = record["timestamp"]

    # storing many records, keyed by name/filename:
    records = {}
    records["alice"] = make_record(
        encrypted_text, hash=hash_value, signature=signature_value, timestamp=timestamp()
    )
    r = records["alice"]   # retrieve one later
    print(r["encrypted"], r["hash"], r["signature"], r["timestamp"])
#
# ---- Writing/reading these dict-shaped records to a FILE ------------------
#
# A record built by make_record() has named fields, not a fixed list in a
# fixed order, so JSON Lines (one JSON object per line -- see the earlier
# "Writing/reading MULTIPLE records" section) is the natural fit here,
# rather than the "|"-delimited format. json.dumps/json.loads handle even
# a huge RSA signature integer correctly (verified below), no extra work
# needed to convert it to/from text first.
if False:
    import json

    def write_record_to_file(filename, record):
        with open(filename, "a") as f:              # "a" = append, keeps earlier records
            f.write(json.dumps(record) + "\n")

    def read_records_from_file(filename):
        records = []
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    # writing one record per patient, as they're created:
    write_record_to_file("records.jsonl", make_record(
        encrypted_text, hash=hash_value, signature=signature_value, timestamp=timestamp()
    ))

    # reading them all back later:
    for record in read_records_from_file("records.jsonl"):
        print(record["encrypted"], record["hash"], record["signature"], record["timestamp"])
#
# Verified with a real 2048-bit-RSA-sized signature (a 600+ digit integer)
# written and read back byte-for-byte identical -- JSON has no size limit
# on integers, unlike some other languages' number types.


# == 4. STRING VS BYTES: know which flavor a file expects ==================
#
#   STRING-in / STRING-out (most files -- plug a message straight in):
#       aes.py, aes128.py, des.py, tripledes.py, rsa.py, rsa_given_keys.py,
#       rsa_signature.py, ecc.py, elgamal.py, rabin.py, all classical ciphers.
#
#   RAW BYTES (for file/binary work):
#       file_transfer.py, hospital_management.py -- their aes_encrypt /
#       aes_decrypt take/return `bytes`, not `str`.
#
#   Converting between them:
#       s.encode()          str  -> bytes
#       b.decode()          bytes -> str
#       b.hex()             bytes -> hex str
#       bytes.fromhex(s)    hex str -> bytes


# == 5. GOTCHAS ==============================================================
#
#  "Data too long for key size" (RSA)
#       -> message is bigger than the key allows. Use the hybrid pattern
#          (section 3) instead of shrinking the message.
#
#  AES key must be exactly 16, 24, or 32 bytes
#       -> if given an arbitrary-length string as a key, normalize it:
if False:
    key = text.encode()[:16].ljust(16, b"\0")   # see medisecure.py
#
#  Hex key given, not text
#       -> use bytes.fromhex(key), NOT key.encode() -- encoding a hex
#          STRING as ASCII gives the wrong bytes entirely.
#          (see aes128.py's comment on this exact trap)
#
#  Triple DES with all three key-thirds equal
#       -> pycryptodome's DES3 refuses this as a "degenerate key".
#          tripledes.py implements DES3-EDE by hand with plain DES calls
#          instead, which has no such restriction.
#
#  Rabin decryption gives 4 possible roots
#       -> need a redundancy check to pick the right one; rabin.py uses
#          "root must be a valid ASCII byte (<256)" as that check.
#
#  ElGamal/RSA with a small given prime/modulus
#       -> encrypt per-character (each character's ASCII code must be less
#          than the modulus), not the whole message as one integer.
#          elgamal.py and rsa_given_keys.py already do this.
#
#  Vigenere/Autokey/etc. crash with "substring not found"
#       -> the key or ciphertext has uppercase letters or non-alphabetic
#          characters that A.index() can't find in the lowercase alphabet.
#          Every function in reference/ already lowercases+filters its own
#          inputs, so this shouldn't happen unless you write new code that
#          skips that step.
#
#  pow(x, -1, m)
#       -> computes a modular inverse directly (Python 3.8+). Don't
#          hand-roll extended Euclid unless the question asks you to show
#          the steps.
#
#  Diffie-Hellman is not a signature scheme
#       -> "digital signatures using Diffie-Hellman" means DSA
#          (dh_signature.py), not dh.py.


# == 6. BLOCK CIPHER MODES (ECB / CBC / CFB / OFB / CTR) ====================
#
# Every DES/AES file in ciphers/ demonstrates ONE mode (ECB or CBC). If a
# question specifically names a different mode, only the AES.new(...)/
# DES.new(...) line changes -- pad/unpad/encrypt/decrypt stays the same
# shape. CFB, OFB and CTR are stream-like: no padding needed at all.
#
if False:
    from Crypto.Cipher import AES, DES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes

    # ECB -- no IV. (ciphers/des.py's default mode)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))

    # CBC -- needs an IV of exactly block_size bytes. (ciphers/aes.py's
    # default mode; DES.block_size is 8, AES.block_size is 16)
    cipher = DES.new(key, DES.MODE_CBC, iv)          # iv: 8 bytes for DES
    cipher = AES.new(key, AES.MODE_CBC, iv)          # iv: 16 bytes for AES
    ciphertext = cipher.encrypt(pad(data, cipher.block_size))
    # decrypt: make a FRESH cipher object with the same key+iv, then
    # unpad(cipher.decrypt(ciphertext), cipher.block_size)

    # CFB / OFB -- also take an IV, but NO padding (stream-like modes):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(data)                # no pad()
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(data)                # no pad()

    # CTR -- takes a `nonce` instead of an iv (nonce is block_size - 8
    # bytes; omit it and pycryptodome generates one, but then you must read
    # it back off cipher.nonce to decrypt). No padding.
    nonce = get_random_bytes(8)                      # for AES: 16 - 8 = 8 bytes
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(data)
    cipher2 = AES.new(key, AES.MODE_CTR, nonce=nonce)  # same nonce to decrypt
    plaintext = cipher2.decrypt(ciphertext)
#
# In every mode: make a NEW cipher object for decryption (with the same
# key/iv/nonce) rather than reusing the encryption one -- pycryptodome
# cipher objects are single-use and track their own internal state.


# == 7. CLASSICAL CIPHER CRYPTANALYSIS (attacks, not just enc/dec) =========
#
# Lab 1's own exercises are about BREAKING ciphers, not just using them --
# this could resurface as its own question or as part of a bigger scenario
# ("show the key management is weak by breaking the cipher it protects").
#
# Known plaintext-ciphertext pair -> solve directly (no searching needed):
if False:
    import string
    A = string.ascii_lowercase
    # additive cipher: C = (P + key) mod 26  =>  key = (C - P) mod 26
    key = (A.index(known_cipher_char) - A.index(known_plain_char)) % 26
    # affine cipher C = (a*P + b) mod 26 needs TWO known pairs to solve for
    # (a, b) -- set up two equations and solve, or just brute-force `a`
    # over Z26* (a must be coprime with 26: 1,3,5,7,9,11,15,17,19,21,23,25)
    # and check which one, combined with the corresponding b, fits BOTH pairs.
#
# No known plaintext -> brute force (only 26 keys for additive/Caesar, so
# just print every candidate and read off the one that's English):
if False:
    import string
    A = string.ascii_lowercase

    def brute_force_additive(ciphertext):
        ciphertext = ''.join(c for c in ciphertext.lower() if c.isalpha())
        for key in range(26):
            candidate = ''.join(A[(A.index(c) - key) % 26] for c in ciphertext)
            print(f"key={key:2d}: {candidate}")
#
# Multiplicative cipher brute force: only keys coprime with 26 are valid
# (1,3,5,7,9,11,15,17,19,21,23,25 -- 12 possible keys), same idea: try each,
# print, read off the English one.
#
# Keyed transposition, chosen-plaintext attack (Lab 1's Eve example: typing
# "abcdefghi" and reading off where each letter landed): the ciphertext
# positions directly reveal the permutation key -- the size of the key is
# just the length of the block the cipher rearranges (count the letters
# before the output starts repeating a pattern / before it wraps around).


# == 8. RSA / KEY-GENERATION VULNERABILITIES (attack demonstrations) =======
#
# "Demonstrate an attack because the keys were generated badly" is a
# plausible scenario question -- it inverts the usual "build a secure
# system" framing into "break an insecure one, then explain the fix".
#
# Weak keys: p and q are too close together (Fermat factorization).
# If p ~ q, then n = p*q is close to a perfect square, so a = ceil(sqrt(n))
# gives a - p and a - q that are both small -- this converges in very few
# iterations when p, q are close, and is hopeless (as intended) when they
# aren't.
if False:
    import math

    def fermat_factor(n):
        a = math.isqrt(n) + 1
        b2 = a * a - n
        while math.isqrt(b2) ** 2 != b2:
            a += 1
            b2 = a * a - n
        b = math.isqrt(b2)
        return a - b, a + b   # p, q

    p, q = fermat_factor(n)                    # recovers the two primes
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)                        # recovers the private exponent
    recovered_message = pow(ciphertext, d, n)  # decrypts anything encrypted with n
#   Mitigation to state in an answer: generate p and q independently with
#   enough bits (>= 1024 each for real use) and no closeness constraint --
#   e.g. reject and re-sample if abs(p - q) is small, which is what proper
#   prime-generation libraries already guard against.
#
# Common modulus attack: the SAME message was sent to two recipients who
# share the same n but use different (coprime) public exponents e1, e2.
# Anyone who captures both ciphertexts can recover the message with NEITHER
# private key, using the extended Euclidean algorithm to write
# a*e1 + b*e2 = 1, then m = c1^a * c2^b mod n (handling a negative exponent
# via a modular inverse first, since pow() needs a non-negative exponent
# unless the modulus argument makes the base invertible):
if False:
    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x1, y1 = egcd(b, a % b)
        return g, y1, x1 - (a // b) * y1

    g, a, b = egcd(e1, e2)                     # g must be 1 (e1, e2 coprime)
    part1 = pow(c1, a, n) if a >= 0 else pow(pow(c1, -1, n), -a, n)
    part2 = pow(c2, b, n) if b >= 0 else pow(pow(c2, -1, n), -b, n)
    recovered_message = (part1 * part2) % n
#   Mitigation: never reuse the same modulus n across different keypairs/
#   recipients -- each party needs their own independently generated n.
#
# Low public exponent attack (e=3, no padding, short message): if
# m**3 < n (message small relative to key size), the ciphertext c = m**3
# with NO modular wraparound, so m is just the exact integer cube root of
# c -- recoverable with no key at all. Mitigation: always use OAEP padding
# (like ciphers/rsa.py does) and/or a standard exponent like 65537.


# == 9. TIME-LIMITED / REVOCABLE ACCESS CONTROL (DRM-style patterns) =======
#
# A plausible variant on the role-based-access theme (section 3): instead
# of fixed roles, access is per (user, resource) and can expire or be
# revoked individually -- e.g. a DRM system granting a customer 48 hours
# to watch a video, or a hospital granting a locum doctor 1-day access.
if False:
    from datetime import datetime, timedelta

    grants = {}   # (user, content) -> {"expires_at": ..., "revoked": False}

    def grant_access(user, content, duration_hours):
        grants[(user, content)] = {
            "expires_at": datetime.now() + timedelta(hours=duration_hours),
            "revoked": False,
        }

    def revoke_access(user, content):
        if (user, content) in grants:
            grants[(user, content)]["revoked"] = True

    def is_access_valid(user, content):
        grant = grants.get((user, content))
        if not grant or grant["revoked"]:
            return False
        return datetime.now() < grant["expires_at"]
#   Combine with any encrypt/decrypt pair from ciphers/: only call the
#   decrypt function after is_access_valid(...) returns True, exactly like
#   medisecure.py's Doctor role only decrypts after both checks pass.


# == 10. CIA TRIAD CHECKLIST (confidentiality + integrity + authenticity) ==
#
# "Demonstrate the CIA triad" is named explicitly as an additional exercise
# in the lab manual, so a direct question ("build a system that
# demonstrates confidentiality, integrity and authenticity") is plausible
# on its own, not just as a side-effect of a bigger scenario. It's the same
# ingredients as medisecure.py, just framed around the three properties by
# name instead of around roles:
#
#   Confidentiality -> encrypt the message. Any cipher works; RSA/AES/ECC
#                       are the usual picks (ciphers/rsa.py, aes.py, ecc.py).
#   Integrity       -> hash the ciphertext (ciphers/hashing.py's
#                       sha256_hash) and let the receiver recompute +
#                       compare it. Show a tamper demo (tamper_hex /
#                       tamper_bytes in glue_snippets.py) to prove the
#                       check actually catches corruption.
#   Authenticity    -> sign the hash with the sender's RSA private key
#                       (ciphers/rsa_signature.py's rsa_sign/rsa_verify) so
#                       the receiver can confirm WHO sent it, not just that
#                       it's unmodified. Verify with the sender's PUBLIC key.
#
# Order of operations on the sending side: encrypt -> hash the ciphertext
# -> sign the hash. On the receiving side (in this order, stop early if any
# check fails): recompute the hash and compare (integrity) -> verify the
# signature against the sender's public key (authenticity) -> only then
# decrypt (confidentiality preserved until both checks pass).


# == 11. SOCKETS CARRYING MORE THAN ONE THING AT ONCE =======================
#
# The socket skeleton in section 3 sends one string. A combined scenario
# (encrypted + hashed + signed document over a socket) just needs multiple
# pieces joined with a delimiter that won't appear in any of them, then
# split back apart on the other end -- exactly what signature_server.py /
# signature_client.py already do for "document|signature":
if False:
    # sender
    payload = f"{ciphertext_hex}|{hash_hex}|{signature}"
    conn.sendall(payload.encode())

    # receiver
    ciphertext_hex, hash_hex, signature = conn.recv(4096).decode().split("|")
    signature = int(signature)
#   If any piece could itself contain "|" (it won't for hex strings or
#   decimal integers, which is everything ciphers/ produces), send a fixed
#   4-byte length prefix before each piece instead of relying on a
#   delimiter -- but for hex/int payloads the delimiter approach is fine
#   and much less code to get right under time pressure.


# == 12. GENERALIZED PERFORMANCE BENCHMARK TEMPLATE =========================
#
# des_vs_aes256.py's `measure()` helper works for ANY function, not just
# DES/AES -- reuse it whenever a question asks to "measure/compare the time
# taken" for arbitrary operations (key generation, encryption, signing, ...):
if False:
    import time

    def measure(fn, *args, repeats=1000):
        start = time.perf_counter()
        for _ in range(repeats):
            result = fn(*args)
        elapsed = time.perf_counter() - start
        return result, elapsed / repeats

    # example: compare RSA vs ElGamal key generation time
    _, rsa_keygen_time = measure(rsa_generate_keys, repeats=5)
    _, elgamal_keygen_time = measure(elgamal_generate_keys, repeats=5)
#   Lower `repeats` for anything slow (RSA/DH/Rabin key generation, ECC) --
#   5-20 repeats is plenty to see a clear difference; reserve repeats=1000+
#   for genuinely fast operations like a single AES block encrypt.
