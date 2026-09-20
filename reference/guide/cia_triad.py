# =============================================================================
#  CIA TRIAD  --  confidentiality, integrity, authenticity
# =============================================================================
#  "Demonstrate the CIA triad" is an exercise in the lab manual, and every
#  system question (MediSecure, HealthSecure, ...) is these three ideas in a
#  costume.
#
#   Confidentiality  Encrypt the message.
#                    ciphers/aes.py, rsa.py, ecc.py  (long data: hybrid)
#
#   Integrity        Hash the CIPHERTEXT. The receiver recomputes the hash and
#                    compares. Prove it works with a tamper demo.
#                    ciphers/hashing.py, glue_snippets.tamper_hex
#
#   Authenticity     Sign the hash with the sender's PRIVATE key. The receiver
#                    verifies with the sender's PUBLIC key, which proves WHO
#                    sent it, not just that it is unchanged.
#                    ciphers/rsa_signature.py
#
#  Sender:    encrypt -> hash the ciphertext -> sign the hash
#  Receiver:  recompute the hash -> verify the signature -> decrypt
#             (stop at the first failed check; never decrypt on a failure)
#
#  Roles that must NOT see the plaintext (Nurse, Admin, Auditor) can still run
#  the first two receiver steps, because those work on the ciphertext alone:
#  system_parts/integrity_and_signature.py -> verify_record()
#
#  Fully assembled: problems/medisecure.py, problems/hospital_management.py
