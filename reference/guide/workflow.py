# =============================================================================
#  EXAM WORKFLOW  --  turning a question into code, step by step
# =============================================================================
#  (Comments only: safe to open or run. Where to find things: which_file.py)
#
#  1. IDENTIFY the algorithms the question names (AES, RSA, ElGamal, SHA-256,
#     signature, ...) and look each up in which_file.py.
#
#  2. GIVEN or GENERATE? If the question hands you a key / modulus / p,g,h /
#     IV, use those numbers and skip the generate_*() call.
#     (which_file.py, section "Given numbers vs. generate")
#
#  3. COPY the functions you need from ciphers/ exactly as they are
#     (generate_key -> encrypt -> decrypt -> sign / verify). Don't tidy them
#     while pasting; that's where typos come from.
#
#  4. CHECK TYPES. Almost every cipher file is string-in / string-out, so a
#     typed message or key needs no conversion. aes.py's aes_encrypt(key,
#     plaintext, iv=None) takes a str OR bytes key and an optional given iv.
#
#  5. ADD THE PARTS AROUND THE CIPHER:
#       - key / IV typed by the user   -> ciphers/glue_snippets.normalize_bytes
#       - "record when"                -> ciphers/glue_snippets.timestamp
#       - "show integrity failure"     -> ciphers/glue_snippets.tamper_hex
#       - store / read text files      -> files/text_files.py
#       - records with named fields    -> files/json_files.py
#       - encrypt + hash + sign, and check without decrypting
#                                      -> system_parts/integrity_and_signature.py
#       - menus and roles              -> system_parts/role_menu.py
#       - long data with RSA           -> system_parts/hybrid_encryption.py
#       - key generate/revoke/renew    -> system_parts/key_management.py
#       - expiring / revocable access  -> system_parts/access_control.py
#       - client and server            -> system_parts/socket_helpers.py
#       - "measure the time"           -> system_parts/benchmark.py
#
#  6. WIRE IT UP in the order the question lists its steps, and RUN the file
#     after each new piece (after encrypt, after hash, after decrypt) instead
#     of debugging 80 lines at once.
#
# -----------------------------------------------------------------------------
#  WORKED EXAMPLE
# -----------------------------------------------------------------------------
#  "AES with a user-typed key + IV, hash the ciphertext, sign the hash with
#   RSA, verify then decrypt, then show what happens if it's tampered with."
#
#     1. AES, SHA-256, RSA signature, tamper demo.
#     2. Key + IV are given (typed, any length) -> normalize_bytes.
#        RSA keys are not given -> rsa_generate_keys().
#     3. Copy from ciphers/: aes.py, rsa.py, rsa_signature.py, hashing.py.
#     4. Everything is plain strings: no conversion needed.
#     5. Copy the pipeline from system_parts/integrity_and_signature.py, and
#        normalize_bytes / tamper_hex from ciphers/glue_snippets.py.
#     6. encrypt -> sha256_hash(ciphertext) -> rsa_sign(hash)
#        receiver: recompute the hash and compare; rsa_verify(hash, sig, e, n);
#        only if both match -> aes_decrypt
#        tamper: tamper_hex(ciphertext), rehash, show the comparison fails.
#
#     Fully assembled: problems/medisecure.py
#
# -----------------------------------------------------------------------------
#  If the question is "similar but different" from a file in problems/, open
#  the closest one and change the messages / keys in its
#  `if __name__ == "__main__":` block. The functions rarely need to change.
