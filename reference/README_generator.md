# Exam code generator — how to use it

`reference/generate.py` asks you questions about the exam question, then writes
**one complete, runnable Python program** for it and tests that program
automatically. No AI is involved: every cipher function in the output is copied
word-for-word from `reference/ciphers/`, and everything else comes from fixed,
tested templates.

---

## 1. Quick start

```bash
cd reference
python generate.py                      # answer the questions -> writes + tests the program
python generate.py --list               # list the ready-made sample questions
python generate.py --preset medisecure  # build a sample question directly
```

When it finishes you see:

```
Wrote /…/exam_solution.py (812 lines)
Running its self-test ...
   | SELF-TEST PASSED
SELF-TEST PASSED
Run it:  python exam_solution.py
```

Then run the program and show it:

```bash
python exam_solution.py          # the menu you demonstrate in the exam
python exam_solution.py test     # runs every action by itself (proves it works)
```

**Press Enter to accept the `[default]` shown in brackets.**
Made a mistake while answering? Press **Ctrl+C** and start again — nothing is
written until the last question.

---

## 2. Recommended exam workflow (about 10 minutes)

1. **Read the question** and underline: the roles, the fields, each algorithm
   (encryption, hash, signature, homomorphic), "store in a file", "timestamp",
   "verify before decrypt", "search", given numbers.
2. **Is it close to a sample?** Run `python generate.py --list`. If one is close,
   start from it (`--preset name`) — otherwise answer the questions.
3. **Generate**, wait for `SELF-TEST PASSED`.
4. **Edit the lines marked `TODO` / `CHANGE:`** in the output (given p/g/x
   numbers, candidate names, constraints).
5. **Run the menu**, go through each role, use the *(demo) Tamper* option to show
   that verification catches changes.

---

## 3. The two kinds of question

The first question picks the kind:

| Choice | Use it for | Examples |
|---|---|---|
| **1) record system** | anything that stores records and has roles: encrypt + hash + sign + store, then verify / decrypt / search / homomorphic totals | MediSecure, HealthSecure, SecureVault, Hospital, E-voting, payroll, grant portal |
| **2) key exchange + classical cipher** | Diffie-Hellman shared secret, then affine / additive / multiplicative on A-Z text | FieldTrack |
| **3) a sample question** | start from a preset | see section 6 |

---

## 4. Every question, in order (record system)

Questions that don't apply are skipped automatically (e.g. no IV question for RSA).

### Basics

| Question | What to answer |
|---|---|
| System name | the name in the question, e.g. `MediSecure` |
| What is ONE stored item called | `record`, `ballot`, `document`, `patient record` … (used in menu text) |
| Name of its ID field | e.g. `Patient ID`. **Don't repeat the ID in the next question.** |
| OTHER data fields to encrypt | comma separated: `Name, Age:int, Report:file`<br>`:int` = a number (needed for homomorphic maths)<br>`:file` = the value is read from a `.txt` file |
| Any CONSTRAINTS on the fields? | `y` if the question gives rules (see 4a) |

#### 4a. Field constraints

Pick the fields (by name or number, the ID counts too), then a rule for each:

| Field | Rules |
|---|---|
| text | letters only · digits only · letters + digits · email · 10-digit phone · date YYYY-MM-DD · one of a list · custom regex (asks for 3 examples) — plus min / max length |
| number | minimum / maximum |

The program re-asks with the reason: `INVALID Age: must be at most 120`.

### Encryption

| Question | What to answer |
|---|---|
| Encrypt the data with | AES-128/192/256, DES (CBC), 3DES, RSA (short data only), ElGamal, ECC, Rabin |
| Where does the key come from? | random · typed once at start · typed when encrypting AND decrypting · **a password per record** (PBKDF2, only salt + check value stored) |
| Encrypt the key with RSA? | no · **fresh key per record, RSA-encrypted inside the record** (hybrid) · **one key, RSA-encrypted and saved to its own file** ("AES key encrypted with RSA and stored in a file") |
| RSA key size | e.g. `4096` if the question says RSA-4096 |
| IV | random per record · typed by the user |
| ElGamal parameters given? | type `p,g,x` from the question, or Enter to generate |
| Encrypt some fields with a DIFFERENT algorithm? | e.g. Diagnosis with RSA, Name with ElGamal — each such field gets its own ciphertext |

### Integrity and signatures

| Question | What to answer |
|---|---|
| Hash | SHA-256 · SHA-512 · SHA-1 · MD5 |
| Hash of | **the ciphertext** (can be checked without decrypting — usual) · the plaintext (receiver decrypts, then re-hashes — e.g. "hash of the ballot") |
| Digital signature | none · RSA · ElGamal · Schnorr · DSA |
| sign the hash TOGETHER with the timestamp? | `n` (default) = sign only the hash · `y` = sign hash\|timestamp ("trusted timestamp") |
| Does every user sign with their OWN key pair? | `y` if each doctor / client signs with their own key; the record stores who signed |
| add a 'Countersign' action? | `y` for "the supervisor also signs" |
| A separate small value encrypted with ElGamal? | e.g. an authorization code; can use given p, g, x |

### Homomorphic operations (lab 7)

Add as many as you need; each becomes its **own menu action**. Pick `done` to stop.

| Scheme | Operations |
|---|---|
| Paillier | SUM, AVERAGE, SUM × k, add k to each, multiply each by k, DIFFERENCE of two records, "is it above T?" (value stays hidden), vote count per candidate |
| textbook RSA | PRODUCT, PRODUCT × k, multiply each by k, power k |
| ElGamal | PRODUCT, PRODUCT × k, multiply each by k, power k |
| exponential ElGamal | SUM (small totals) |

For each operation you are asked **which records it uses**:

| Answer | The role then types |
|---|---|
| always ALL records | nothing |
| the role types a list of IDs | `IDs, comma separated:` |
| a FIXED field filter | e.g. `Department =` (through the plain / SSE / PKSE index you pick) |
| let the role choose each time | a 1 / 2 / 3 menu |

Not possible with these schemes (so not offered): Paillier ciphertext × ciphertext,
RSA addition, plain ElGamal addition.

**Threshold decryption: number of trustees** — e.g. `3` for "decrypt only the final
aggregate with the trustees' shares" (all trustees are needed).

### Search (lab 8) and time

| Question | What to answer |
|---|---|
| Search | none · plain index only · plain + SSE · plain + PKSE · plain + SSE + PKSE |
| search by which field(s) | e.g. `Constituency` |
| also search by time range? | `y` for "search by time range" |
| Must the timestamp be inside a time window? | `y` for a deadline / voting period (records outside it fail verification) |

Search results always show the **complete** stored record (ciphertext, hash,
signature …).

### Roles and access

| Question | What to answer |
|---|---|
| Role-based (RBAC) menus? | `y`, then role names, then for each role the numbers of its actions from the printed list |
| Must users LOG IN? | `y` for username + password before a role (salted PBKDF2) |
| Allow decryption only inside a time window? | `y` for "decrypt only after the exam starts" |
| Also run as a socket server / client? | `y` for client/server questions |

Typical action choices per role:

| Role style | Actions |
|---|---|
| creates data (Patient, Client, Voter, Sender) | Add, View, Import |
| reads data (Doctor, Lawyer, Receiver) | Verify, Verify-then-decrypt |
| checks only (Nurse, Auditor, Compliance) | Verify, Compliance report, View IDs/hashes/VALID |
| statistics (Finance, Trustees) | the homomorphic actions |

### Files and output

| Question | What to answer |
|---|---|
| Keep keys between runs? | `y` (default): keys saved on the first run and reused — old records still verify |
| Append every decrypted record to a history file? | `y` (default) |
| Keep an access log? | `y` (default) |
| Read inputs from a .txt file? | `y` for "read the records from a file" (see 7c) |
| Print every calculation? | `y` (default) shows keys, IV, ciphertexts, hashes, signatures, totals |
| Output file | e.g. `medisecure.py` |

At the end the generator prints your answers as one line of JSON. Paste it into
`PRESETS` in `generate.py` to rebuild the same program later with `--preset`.

---

## 5. Key-exchange questions (FieldTrack style)

| Question | Example |
|---|---|
| DH prime p, generator g | `23`, `5` |
| Sender / Receiver private key | given numbers, or Enter for random |
| Cipher on A-Z text | affine (k1 typed + validated) · additive · multiplicative |
| k2 given in the question | `2` (checked against K mod 26), or Enter to use K mod 26 |

The program checks both shared secrets match, cleans the text to A-Z, rejects an
invalid k1 (gcd ≠ 1) and asks again, shows k1's inverse, and decrypts on the
receiver side.

---

## 6. Ready-made presets

```bash
python generate.py --list
python generate.py --preset evoting            # writes evoting.py and tests it
python generate.py --preset hospital --out hosp.py --no-test
```

| Preset | What it builds |
|---|---|
| `evoting` | AES-256 ballot, RSA-4096 wrapped key, SHA-512 of the ballot, ElGamal signature, Paillier votes, 3-trustee threshold tally, SSE + PKSE search by constituency and time, voting period |
| `employee` | every homomorphic operation (Paillier, RSA, ElGamal), all record-selection modes, plain/SSE/PKSE search |
| `securevault` | DES-CBC, SHA-256 of ciphertext, ElGamal signature; Client / Lawyer / Compliance Officer |
| `healthsecure` | RSA-encrypted fields, SHA-256, RSA signature; Doctor / Nurse / Admin |
| `hospital` | file → AES-128, AES key RSA-encrypted in a file, ElGamal auth code with given p,g,x |
| `medisecure` | AES with typed key + IV, SHA-256, RSA signature; Patient / Doctor / Auditor |
| `grant` | AES-192, Paillier sum of amounts, MD5, RSA signature, SSE search |
| `fieldtrack` | Diffie-Hellman + affine with k1/k2 checks |

Options: `--out file.py` (output name), `--no-test` (skip the self-test),
`--force` (overwrite without asking).

> Hand-written, shorter versions of the past exam questions are also in
> `reference/templates/` — open one, edit the lines marked `CHANGE:`.

---

## 7. The generated program

### 7a. How to run it

```bash
python exam_solution.py                          # menu
python exam_solution.py test                     # self-test: every action, tamper, restart
python exam_solution.py --answers answers.txt    # if "read inputs from a .txt file" = y
python exam_solution.py server                   # if sockets = y (in one terminal)
python exam_solution.py client                   # if sockets = y (in another terminal)
```

### 7b. Where to change things

The top of the file describes the record layout, the roles and the run commands.
Search for:

| Marker | Meaning |
|---|---|
| `TODO` / `CHANGE:` | numbers or names to copy from the question (given p, g, x · candidates · constraints) |
| `EDIT ZONE 1: which crypto` | every encrypt / decrypt / hash / sign / verify call, in one place |
| `EDIT ZONE 2: what is hashed and signed` | `hashed_part`, `signed_part`, `check_record` |
| `EDIT ZONE 3: menu actions` | one function per menu action |
| `SHOW_STEPS = True` | print every calculation (set `False` for shorter output) |

### 7c. Inputs from a .txt file (if you answered `y`)

**Import records** (menu action): one record per line, values in the order shown
at the top of the generated file, e.g.

```
P1, Asha, Flu
P2, Ravi, Diabetes
# lines starting with # are ignored
```

Every record is encrypted, hashed and signed exactly as if typed. Bad lines are
skipped with a reason (wrong number of values, duplicate ID, value breaking a
constraint).

**Answers file**: `python exam_solution.py --answers answers.txt` — each line
answers the next question (menu choices, IDs, values …); the keyboard takes over
when the file runs out.

### 7d. Files it creates (next to the program)

| File | Contents |
|---|---|
| `<name>_records.txt` | the encrypted records, one per line, fields joined with `\|` |
| `<name>_keys.txt` | all keys (if "keep keys between runs") |
| `<name>_access_log.txt` | time \| role \| action \| ID \| result |
| `<name>_decrypted.txt` | history of every successful decryption |
| `<name>_report.txt` | the compliance report |
| `<name>_*_index.txt` | plain / SSE / PKSE search indexes |
| `<name>_wrapped_key.txt` | the RSA-encrypted AES key (if "one key in its own file") |
| `<name>_users.txt` · `<name>_signer_keys.txt` | logins (salted hashes) · each signer's key pair |

---

## 8. Safety rules the generated code always follows

- **Verify before decrypt.** Nothing is decrypted if the hash, signature or time
  check fails (tested by counting decrypt calls on tampered records).
  If the hash is of the *plaintext*, verification must decrypt — it does so
  silently, and the plaintext is shown only after every check passes.
- **Keys are made once**, never inside the menu loop.
- **Every sign / verify has the same shape:** `X_sign(message, private) -> str`,
  `X_verify(message, signature, public) -> True/False`, and a signature read back
  from a file as text just works.
- **Tamper demo**: changes one character of a stored ciphertext; every check then
  reports `INVALID` and decryption is refused.

---

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| `The keys file is from a different version of this program` | you regenerated with different answers: delete `<name>_keys.txt` **and** `<name>_records.txt` |
| An ID "already exists" on a new run | keys and records are kept between runs — delete the records file to start fresh |
| `Output file exists. Overwrite?` | answer `y`, use `--force`, or pick another name |
| `SELF-TEST FAILED` | read the last lines it prints; usually a typo in a field name or an impossible constraint |
| Output too long to read | set `SHOW_STEPS = False` in the generated file |
| `RSA ... Data too long` | RSA can only encrypt short text: use AES + "encrypt the key with RSA" instead |
| Relative file paths not found | run from the program's folder (`cd` there) or give the full path |

---

## 10. What still needs a few hand edits

The generator covers the usual structure; a question can still ask for something
unusual (e.g. "Admin can only see today's records"). Put that logic into the
matching function in **EDIT ZONE 3**, run `python exam_solution.py test` again,
and keep the verify-before-decrypt order. Single-algorithm questions ("encrypt
with Playfair") don't need the generator — use the matching file in
`reference/ciphers/` (see `guide/which_file.py`).
