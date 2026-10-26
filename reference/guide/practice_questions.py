# =============================================================================
#  PRACTICE QUESTIONS  (mid-sem / end-sem style, labs 1-8)
# =============================================================================
#  EVERY question below has a complete, tested program in
#  templates/practice/qNN_<name>.py  (python qNN_<name>.py test).
#  Q1-Q11 and Q13 are also generator presets: python generate.py --preset <name>
#
#  New scenarios in the style of the real papers (MediSecure, SecureVault,
#  HealthSecure, Hospital, FieldTrack, E-voting) -- same building blocks,
#  different mixes. Each one says how to build it with generate.py, or
#  "GAP" where the generator cannot do it yet (write that part by hand from
#  ciphers/ and system_parts/, see which_file.py).
#
#  Typical marks split in these papers: crypto correct ~50%, menu/roles/files
#  ~30%, verification + tamper demo + clear output ~20%.
#
#  Index
#    Q1  PharmaChain        Q7  CampusExam         Q13 CipherRelay (sockets)
#    Q2  LegalDocs          Q8  SmartMeter         Q14 KeyVault (key management)
#    Q3  InsureClaim        Q9  BloodBank          Q15 CryptoBench (timing)
#    Q4  CourtEvidence      Q10 ResearchVault      Q16 ClassicTrack (classical chain)
#    Q5  PayrollPlus        Q11 TenderBid          Q17 DocSearch (lab 8 full-text)
#    Q6  CityPoll           Q12 MilitaryRelay      Q18 HashLab (lab 5)
#
#
# -----------------------------------------------------------------------------
# Q1  PharmaChain -- drug batch records                          (labs 2, 5, 6)
# -----------------------------------------------------------------------------
#  Roles: Manufacturer, Distributor, Regulator.
#  Manufacturer: enter Batch ID, drug name, quantity, expiry date. Encrypt the
#    details with AES-192 (key typed once), SHA-512 of the ciphertext, sign
#    with Schnorr, timestamp, store in batches.txt.
#  Distributor: verify hash + signature; decrypt only if both pass; log access.
#  Regulator: verify only, never decrypt; produce a compliance report file.
#  Demo: tamper with one batch and show the Regulator report flags it.
#
#  generate.py: fields "Drug, Quantity:int, Expiry"; aes192, typed_once;
#    sha512 / ciphertext; schnorr; roles Manufacturer[add,view]
#    Distributor[verify,decrypt] Regulator[verify,report,view_meta].
#
# -----------------------------------------------------------------------------
# Q2  LegalDocs -- confidential contracts                       (labs 2, 3, 6)
# -----------------------------------------------------------------------------
#  Roles: Client, Advocate, Auditor.
#  Client: contract text from a .txt file -> 3DES; the 3DES key is
#    RSA-encrypted and stored in its own file; MD5 of the ciphertext; DSA
#    signature; timestamp.
#  Advocate: unwrap the 3DES key with RSA, verify, decrypt, save the decrypted
#    contract history.
#  Auditor: list IDs, timestamps, hashes and VALID/INVALID only.
#
#  generate.py: fields "Contract:file"; 3des; wrap "file"; md5; dsa;
#    roles Client[add] Advocate[verify,decrypt] Auditor[view_meta].
#
# -----------------------------------------------------------------------------
# Q3  InsureClaim -- insurance claims with homomorphic totals   (labs 2, 6, 7)
# -----------------------------------------------------------------------------
#  Roles: Policyholder, Claims Officer, Finance.
#  Policyholder: Claim ID, region, description, claim amount. Description with
#    AES-256 (fresh key per claim, RSA-wrapped), amount with Paillier,
#    SHA-256, RSA signature.
#  Claims Officer: verify + decrypt one claim; check "is the amount above
#    50000?" WITHOUT decrypting the amount.
#  Finance: total and average claim amount for a REGION (filter), decrypt
#    only the totals; payout = total x 0.8 -> use "SUM x constant k" with k
#    as a whole number (e.g. 8, then divide by 10 when printing).
#
#  generate.py: fields "Region, Description, Amount:int"; aes256 wrap record;
#    he: compare(Amount, ask/all), sum(Amount, filter Region), average
#    (Amount, filter Region), scaled_sum(Amount, ids).
#
# -----------------------------------------------------------------------------
# Q4  CourtEvidence -- evidence locker                          (labs 3, 5, 6)
# -----------------------------------------------------------------------------
#  Roles: Investigator, Judge, Clerk.
#  Investigator: evidence description encrypted with ECC (ECIES), SHA-256,
#    ElGamal signature, timestamp. Evidence must be submitted before a
#    deadline (store the deadline; records after it are INVALID).
#  Judge: verify, then decrypt.
#  Clerk: search evidence by case number using a plain index AND SSE;
#    show the complete encrypted record.
#
#  generate.py: fields "Case Number, Description"; ecc; elgamal sig;
#    window "submission deadline"; search sse on Case Number;
#    roles Investigator[add] Judge[verify,decrypt] Clerk[search,view_meta].
#
# -----------------------------------------------------------------------------
# Q5  PayrollPlus -- salaries and bonuses                          (lab 7)
# -----------------------------------------------------------------------------
#  Salary encrypted with Paillier, bonus multiplier with RSA, a second copy of
#  the multiplier with ElGamal.
#  HR: add employees. Manager: increment every salary in a department by
#    2000 (add constant), compute department payroll (sum, filter).
#  Finance: product of multipliers (RSA) and the same with ElGamal; show both
#    decrypt to the same number; raise a multiplier to the power 2.
#  Show the difference between two employees' salaries (can be negative).
#
#  generate.py: preset "employee" covers almost all of it.
#
# -----------------------------------------------------------------------------
# Q6  CityPoll -- municipal referendum                          (labs 6, 7, 8)
# -----------------------------------------------------------------------------
#  Voter: ward + choice (YES / NO / ABSTAIN). Ballot AES-128 with an RSA-2048
#    wrapped key, SHA-256 of the PLAINTEXT ballot, RSA signature, timestamp
#    inside the polling window.
#  Returning Officer: verify all ballots; search ballots by ward (PKSE) and by
#    time range (SSE).
#  Tally Committee of 4 trustees: one-hot Paillier tally, threshold
#    decryption of only the final counts.
#
#  generate.py: like preset "evoting": choices ["YES","NO","ABSTAIN"],
#    aes128 wrap record, sha256 plaintext, rsa sig, trustees 4,
#    search types sse+pkse on Ward, time true, window "polling window".
#
# -----------------------------------------------------------------------------
# Q7  CampusExam -- exam paper distribution                     (labs 2, 3, 5)
# -----------------------------------------------------------------------------
#  Roles: Exam Cell, Invigilator, Student Portal.
#  Exam Cell: question paper (.txt) encrypted with AES-256 using a key the
#    user types; the AES key RSA-encrypted to a file; SHA-256 hash.
#  Invigilator: may decrypt only AFTER the exam start time (time window!)
#    and only if the hash matches.
#  Student Portal: sees paper ID + hash + VALID only.
#
#  generate.py: fields "Paper:file"; aes256 typed_once wrap file; sig none;
#    window "exam window"; roles ExamCell[add] Invigilator[verify,decrypt]
#    StudentPortal[view_meta].
#  The window here gates DECRYPTION time: answer yes to "Allow decryption only
#    inside a time window" (decrypt_window "exam window").
#
# -----------------------------------------------------------------------------
# Q8  SmartMeter -- energy readings                            (labs 5, 6, 7)
# -----------------------------------------------------------------------------
#  Meter: meter ID, zone, kWh reading (Paillier), SHA-1 of the ciphertext,
#    DSA signature.
#  Utility: total kWh per zone (filter, PKSE index), average for chosen IDs,
#    bill = total x tariff (constant k), meters above 500 kWh (threshold).
#
#  generate.py: fields "Zone, Reading:int"; sha1; dsa; he sum (filter Zone
#    via pkse), average (ids), scaled_sum (ids), compare (all).
#
# -----------------------------------------------------------------------------
# Q9  BloodBank -- donor records with per-donor passwords       (labs 2, 5)
# -----------------------------------------------------------------------------
#  Donor: name, blood group, medical notes. Each donor chooses a PASSWORD;
#    the AES key is derived from it (PBKDF2 / SHA-256 with a salt). Store the
#    salt and a password check value, never the password.
#  Doctor: decrypt only after the donor's password is entered correctly.
#  Admin: search donors by blood group (SSE).
#
#  generate.py: key source "a password the user sets for EACH record"
#    (key_src "password"); search sse on Group.
#
# -----------------------------------------------------------------------------
# Q10 ResearchVault -- multi-author papers, each author signs   (labs 3, 6)
# -----------------------------------------------------------------------------
#  Every researcher has THEIR OWN RSA key pair. A paper is AES-encrypted,
#  signed by the submitting researcher, and countersigned by the supervisor.
#  Reviewer verifies BOTH signatures with the right public keys.
#
#  generate.py: "every user signs with their OWN key pair" = yes, and
#    "Countersign" action = yes (user_keys + cosign); add login = yes if the
#    signer should be the logged-in user.
#
# -----------------------------------------------------------------------------
# Q11 TenderBid -- sealed bids                                 (labs 3, 6, 7)
# -----------------------------------------------------------------------------
#  Bidder: company, bid amount. Amount with ElGamal (multiplicative) AND
#    exponential ElGamal; bid text with RSA-OAEP; SHA-256; ElGamal signature;
#    bids only accepted before the closing time.
#  Committee: after closing, compute the sum of all bids (exponential
#    ElGamal), product check (ElGamal), and which bids exceed the reserve
#    price (Paillier threshold -> add a Paillier copy).
#
#  generate.py: enc rsa; he eg_sum, eg_product, compare(Amount);
#    window "bidding window".
#
# -----------------------------------------------------------------------------
# Q12 MilitaryRelay -- DH + affine / Vigenere field messages      (labs 1, 3)
# -----------------------------------------------------------------------------
#  HQ and Unit agree on a Diffie-Hellman key with p = 467, g = 2, private
#  keys given. Message is cleaned to A-Z.
#  Variant A: affine with k1 typed (gcd check, inverse shown), k2 = K mod 26.
#  Variant B: Vigenere with the key word made from the digits of K
#    (0 -> A, 1 -> B, ...).
#  Variant C: Hill 2x2 with a key matrix derived from K, check invertibility
#    mod 26.
#
#  generate.py: kind 2 (key exchange), cipher affine, k2 None.
#  GAP: Vigenere / Hill / Playfair / Autokey as the cipher after DH.
#
# -----------------------------------------------------------------------------
# Q13 CipherRelay -- client/server over sockets                (labs 5, 6)
# -----------------------------------------------------------------------------
#  Client encrypts a message with AES-128 (key RSA-wrapped), hashes it with
#  SHA-256, signs with RSA, sends ciphertext|wrapped key|hash|signature over a
#  TCP socket. Server verifies, decrypts, replies "ACK"/"TAMPERED". Client
#  also sends one deliberately corrupted message.
#
#  generate.py: socket mode = yes (sockets), aes128 wrap record, rsa sig.
#    Run "python file.py server" and "python file.py client"; the client menu
#    has "Send a TAMPERED copy of the last record".
#
# -----------------------------------------------------------------------------
# Q14 KeyVault -- key management service                         (labs 3, 4)
# -----------------------------------------------------------------------------
#  Hospitals register; the KMS generates an RSA (or Rabin) key pair per
#  hospital, stores it, lets an admin revoke or renew a key, and logs every
#  operation. Records encrypted with a revoked key must be refused.
#
#  GAP: per-entity key pairs + revoke / renew / expiry (key rotation).
#  Today: problems/rabin_kms.py, problems/secure_corp.py,
#  system_parts/key_management.py.
#
# -----------------------------------------------------------------------------
# Q15 CryptoBench -- performance comparison                      (labs 2, 3, 7)
# -----------------------------------------------------------------------------
#  Encrypt 1 KB / 10 KB / 100 KB messages with DES, AES-128, AES-256,
#  RSA-hybrid and ECC; time key generation, encryption, decryption; print a
#  table and say which is fastest. Lab 7 variant: Paillier vs ElGamal vs RSA
#  homomorphic operations on 100 numbers.
#
#  GAP: benchmark mode. Today: problems/des_vs_aes256.py,
#  problems/file_transfer.py, system_parts/benchmark.py.
#
# -----------------------------------------------------------------------------
# Q16 ClassicTrack -- chained classical ciphers                     (lab 1)
# -----------------------------------------------------------------------------
#  Encrypt "the house is being sold tonight" with Playfair (key "guidance"),
#  then Vigenere (key "dollars"), then decrypt in reverse. (Playfair first:
#  it turns j into i and adds filler x's, so it cannot sit in the MIDDLE of a
#  chain that must decrypt back exactly.) Then brute-force an additive cipher
#  ciphertext and find the key from a known word.
#
#  GAP: not a generator shape. Today: ciphers/vigenere.py, playfair.py,
#  problems/prac1.py (chaining), attacks/classical_attacks.py.
#
# -----------------------------------------------------------------------------
# Q17 DocSearch -- encrypted document search                         (lab 8)
# -----------------------------------------------------------------------------
#  Ten text documents. Build an encrypted inverted index (word -> doc IDs)
#  with SSE and with PKSE, search for a word typed by the user, decrypt and
#  print the matching documents, and compare search times.
#
#  GAP (partly): the generator indexes whole FIELD values, not every word of
#  a text. Today: ciphers/sse.py and ciphers/pkse.py do exactly this.
#
# -----------------------------------------------------------------------------
# Q18 HashLab -- hashing and integrity                                (lab 5)
# -----------------------------------------------------------------------------
#  Implement the custom hash (start 5381, h = h*33 + c, 32-bit mask), hash 50
#  random strings with MD5, SHA-1, SHA-256 and the custom hash, time them,
#  look for collisions; then send data over a socket and verify the hash on
#  the server.
#
#  GAP: custom hash is not a generator hash option; timing/collisions not a
#  generator shape. Today: ciphers/hash_function.py,
#  problems/hash_comparison.py, hash_server.py + hash_client.py.
