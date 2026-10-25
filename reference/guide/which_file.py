# =============================================================================
#  WHICH FILE DO I OPEN?   (all paths are inside reference/)
# =============================================================================
#  ciphers/       one file per algorithm: generate_key / encrypt / decrypt
#                 (or sign / verify)
#  system_parts/  reusable pieces that system questions are built from
#  attacks/       breaking ciphers and badly set-up RSA
#  files/         plain-text and JSON file read / write
#  problems/      finished example systems (each file is standalone)
#  guide/         these notes
#  generate.py    asks about the scenario, writes a full runnable solution
#                 file + runs its self-test (python generate.py --list for the
#                 sample questions: evoting, employee, securevault,
#                 healthsecure, hospital, medisecure, grant, fieldtrack)
#
# --- ciphers/ ----------------------------------------------------------------
#   Additive / multiplicative / affine cipher          ciphers/primitives.py
#   Vigenere                                           ciphers/vigenere.py
#   Autokey                                            ciphers/autokey.py
#   Playfair                                           ciphers/playfair.py
#   Hill                                               ciphers/hill.py
#   DES                                                ciphers/des.py
#   Triple DES                                         ciphers/tripledes.py
#   AES, any key length (text key, optional given iv)  ciphers/aes.py
#   AES-128 with a given HEX key (32 hex chars)         ciphers/aes128.py
#   AES-192 with a given HEX key (48 hex chars)         ciphers/aes192.py
#   AES-256 with a given HEX key (64 hex chars)         ciphers/aes256.py
#   AES-192 showing every round step                    ciphers/aes192_steps.py
#   AES or DES in ECB / CBC / CFB / OFB / CTR          ciphers/block_modes.py
#   RSA, generate real keys                            ciphers/rsa.py
#   RSA, given raw n / e / d numbers                   ciphers/rsa_given_keys.py
#   RSA digital signature (Alice/Bob lab)              ciphers/rsa_signature.py
#   ElGamal encryption (works with given p,g,h,x)      ciphers/elgamal.py
#   ElGamal signature                                  ciphers/elgamal_signature.py
#   Schnorr signature                                  ciphers/schnorr_signature.py
#   Diffie-Hellman key exchange                        ciphers/dh.py
#   DSA (signature scheme built on DH parameters)      ciphers/dh_signature.py
#   ECC / ECIES encryption                             ciphers/ecc.py
#   Rabin                                              ciphers/rabin.py
#   Paillier (ADD encrypted numbers)                   ciphers/paillier.py
#   Threshold Paillier (trustees decrypt the total)    ciphers/threshold_paillier.py
#   RSA multiplicative homomorphism (7 x 3, x k, ^k)   ciphers/rsa_homomorphic.py
#   ElGamal homomorphic (multiply, x k, ^k; and SUM    ciphers/elgamal_homomorphic.py
#     with exponential ElGamal g^m)
#   Searchable encryption, symmetric (AES + HMAC)      ciphers/sse.py
#   Searchable encryption, public-key (Paillier)       ciphers/pkse.py
#   Custom hash (5381, *33, 32-bit mask)               ciphers/hash_function.py
#   MD5 / SHA-1 / SHA-256 / SHA-512                    ciphers/hashing.py
#   timestamp / normalize key / tamper                 ciphers/glue_snippets.py
#   str/bytes/hex/int/bits conversions                 ciphers/type_conversions.py
#
# --- system_parts/ -----------------------------------------------------------
#   Encrypt + hash + sign; check WITHOUT decrypting    system_parts/integrity_and_signature.py
#   RSA + AES for long data (hybrid)                   system_parts/hybrid_encryption.py
#   Menus, roles, permissions (RBAC)                   system_parts/role_menu.py
#   Generate / revoke / renew keys, audit log          system_parts/key_management.py
#   Expiring / revocable access (DRM style)            system_parts/access_control.py
#   Client + server, several pieces in one message     system_parts/socket_helpers.py
#   Timing comparison table                            system_parts/benchmark.py
#
# --- attacks/ ----------------------------------------------------------------
#   Additive / multiplicative / affine brute force     attacks/classical_attacks.py
#   RSA: close primes, common modulus, low exponent    attacks/rsa_attacks.py
#
# --- files/ ------------------------------------------------------------------
#   Read / write / append text, lines, records         files/text_files.py
#   Records with named fields (dicts) as JSON          files/json_files.py
#
# --- problems/ ---------------------------------------------------------------
#   DES vs AES-256 timing                              problems/des_vs_aes256.py
#   RSA vs ECC file transfer benchmark                 problems/file_transfer.py
#   Enterprise RSA + DH + key management               problems/secure_corp.py
#   Rabin key management service                       problems/rabin_kms.py
#   MD5/SHA-1/SHA-256 timing + collisions              problems/hash_comparison.py
#   Hash integrity over sockets                        problems/hash_server.py + hash_client.py
#   Digital signature over sockets                     problems/signature_server.py + signature_client.py
#   Role-based system (Patient/Doctor/Auditor)         problems/medisecure.py
#   AES+RSA+ElGamal+hash file system, tamper demo      problems/hospital_management.py
#   Chained Vigenere -> AES -> RSA                     problems/prac1.py
#   Encrypted blood-pressure diagnosis (> 130)         problems/secure_diagnosis.py
#   ANY role portal: AES+Paillier+hash+RSA sig, saved  problems/portal_template.py
#     keys, search, hexdump, homomorphic total         (START HERE for new scenarios)
#
#
# =============================================================================
#  GIVEN NUMBERS vs. GENERATE YOUR OWN
# =============================================================================
#  Using the wrong file here is the most common time-waster.
#
#   RSA, given (n, e, d)       -> ciphers/rsa_given_keys.py
#                                 (rsa.py builds real key OBJECTS, which
#                                  reject tiny textbook moduli like n = 323)
#   RSA, "generate a keypair"  -> ciphers/rsa.py, or rsa_signature.py to sign
#   ElGamal, given (p,g,h,x)   -> call elgamal_encrypt / elgamal_decrypt
#                                 directly; skip elgamal_generate_keys().
#                                 It encrypts per character, so even p = 7919
#                                 works.
#   Diffie-Hellman, given p,g  -> skip dh_generate_parameters(); call
#                                 dh_generate_keypair(p, g) once per side.
#   AES key given as HEX       -> ciphers/aes128.py (or bytes.fromhex(key))
#   Homomorphic: ADD encrypted numbers    -> ciphers/paillier.py
#   Homomorphic: MULTIPLY encrypted ones  -> ciphers/rsa_homomorphic.py (NOT rsa.py:
#                                            its OAEP padding breaks the property)
#   Compare encrypted numbers (> / <)     -> Paillier subtract + blind, see
#                                            problems/secure_diagnosis.py
#   "Search encrypted data"               -> ciphers/sse.py (shared key) or
#                                            ciphers/pkse.py (public key)
