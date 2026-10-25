# Secure E-Voting -- exam TEMPLATE
#
# QUESTION
#   Client (voter): ballot = candidate + constituency ID
#       1. SHA-512 hash of the ballot
#       2. AES-256-CBC encrypt the ballot (fresh key per ballot)
#       3. RSA-4096 encrypt that AES key
#       4. ElGamal-sign the SHA-512 hash (with the timestamp: trusted timestamp)
#       5. Paillier-encrypt the candidate (one Enc(0/1) per candidate, so the
#          server can ADD ballots without seeing any of them)
#       6. timestamp
#   Server:
#       1. RSA-decrypt the AES key, decrypt the ballot
#       2. verify the ElGamal signature, recompute SHA-512 and compare
#       3. check the timestamp is inside the voting period
#       4. homomorphic tally of the valid ballots
#       5. searchable encrypted index (SSE) by constituency and by time range
#       6. threshold decryption: ONLY the final totals are decrypted, and only
#          with every trustee's share
#   Menu-driven with RBAC, storage in files, outputs shown for every step.
#
# HOW TO ADAPT -- search for "CHANGE:"
#   - CANDIDATES, TRUSTEES, the voting period, RSA_BITS (4096 is slow-ish: ~2 s)
#   - role names / which role gets which action in main()
#
# Run:  python evoting.py         (menu)
#       python evoting.py test    (runs every action with typed-in answers)

import hashlib
import hmac
import math
import os
import sys
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, getRandomRange
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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


# ---- from ciphers/rsa.py (verbatim, except key_size = RSA_BITS as the question asks) ----

RSA_BITS = 4096                                   # CHANGE: RSA key size from the question


def rsa_generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_BITS
    )
    public_key = private_key.public_key()

    numbers = private_key.private_numbers()

    n = numbers.public_numbers.n
    e = numbers.public_numbers.e
    d = numbers.d

    return private_key, public_key, n, e, d


def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()


def rsa_decrypt(private_key, ciphertext):
    decrypted = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted.decode()


# ---- from ciphers/elgamal_signature.py (verbatim) ----

def _hash_to_int(message, modulus):
    digest = hashlib.sha256(message.encode()).digest()
    return int.from_bytes(digest, "big") % modulus


def elgamal_generate_keys(bits=256):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 2)   # private key
    y = pow(g, x, p)               # public key

    return p, g, y, x


def elgamal_sign(message, p, g, x):
    while True:
        k = getRandomRange(2, p - 2)
        if pow(k, 1, p - 1) != 0 and _egcd(k, p - 1) == 1:
            break

    h = _hash_to_int(message, p - 1)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)

    return str(r) + "," + str(s)


def elgamal_verify(message, signature, p, g, y):
    r, s = _split_signature(signature)
    if not (0 < r < p):
        return False

    h = _hash_to_int(message, p - 1)

    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)

    return v1 == v2


def _egcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _split_signature(signature):
    """A signature is the string "a,b"; numbers or a tuple (e.g. read from a file) work too."""
    if isinstance(signature, str):
        first, second = signature.split(",")
        return int(first), int(second)
    return int(signature[0]), int(signature[1])


# ---- from ciphers/paillier.py + ciphers/threshold_paillier.py (verbatim) ----

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


def paillier_add(n, c1, c2):
    return (c1 * c2) % (n * n)


def threshold_split_key(n, lam, mu, parties):
    """Split the private key into `parties` additive shares (one per trustee)."""
    modulus = n * lam
    d = (lam * mu) % modulus

    shares = [getRandomRange(0, modulus) for _ in range(parties - 1)]
    shares.append((d - sum(shares)) % modulus)

    return shares


def threshold_partial_decrypt(n, ciphertext, share):
    """What ONE trustee computes with its own share."""
    return pow(ciphertext, share, n * n)


def threshold_combine(n, partials):
    """Multiply every trustee's partial result -> the plaintext."""
    product = 1
    for partial in partials:
        product = (product * partial) % (n * n)

    return ((product - 1) // n) % n


# ---- from ciphers/sse.py, ciphers/hashing.py, ciphers/glue_snippets.py (verbatim) ----

def sse_generate_key():
    return get_random_bytes(16)


def sse_trapdoor(key, word):
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def sha512_hash(text):
    return hashlib.sha512(text.encode()).hexdigest()


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ==================== CHANGE: settings ====================

HERE = os.path.dirname(os.path.abspath(__file__))
BALLOTS_FILE = os.path.join(HERE, "evoting_ballots.txt")
INDEX_FILE = os.path.join(HERE, "evoting_index.txt")

CANDIDATES = ["Alice", "Bob", "Carol"]     # CHANGE: candidate list (candidate ID = position + 1)
TRUSTEES = 3                               # CHANGE: number of trustees (ALL are needed to decrypt)

# one ballot per line: voter_id|enc_ballot|wrapped_key|votes|time|hash|signature
FIELDS = ["voter_id", "enc_ballot", "wrapped_key", "votes", "time", "hash", "signature"]

K = {}


def setup_keys():
    print("Generating keys (RSA-%d takes a moment)..." % RSA_BITS)
    K["rsa_priv"], K["rsa_pub"], _, _, _ = rsa_generate_keys()
    K["eg_p"], K["eg_g"], K["eg_y"], K["eg_x"] = elgamal_generate_keys()
    K["pa_n"], K["pa_g"], lam, mu = paillier_generate_keys(1024)
    K["shares"] = threshold_split_key(K["pa_n"], lam, mu, TRUSTEES)   # lam/mu are NOT kept anywhere
    K["sse"] = sse_generate_key()
    now = datetime.now()
    K["start"] = now.strftime("%Y-%m-%d %H:%M")                       # CHANGE: voting period start
    K["end"] = (now + timedelta(days=1)).strftime("%Y-%m-%d %H:%M")   # CHANGE: voting period end
    show("ElGamal public key y", K["eg_y"])
    show("Paillier public n", K["pa_n"])
    show("trustee shares", str(TRUSTEES) + " shares (private key split)")
    show("voting period", K["start"] + " .. " + K["end"])


# ---------- the client (voter) side ----------

def ballot_text(candidate, constituency):
    return "candidate=" + candidate + ";constituency=" + constituency


def encrypt_votes(candidate):
    """Paillier one-hot: Enc(1) for the chosen candidate, Enc(0) for the others."""
    return ";".join(str(paillier_encrypt(K["pa_n"], K["pa_g"], 1 if c == candidate else 0)) for c in CANDIDATES)


def index_ballot(voter_id, constituency, time_text):
    """SSE: HMAC tokens for 'constituency=..' and 'hour=..' -> AES-encrypted voter ID."""
    with open(INDEX_FILE, "a", encoding="utf-8") as f:
        for word in ("constituency=" + constituency.lower(), "hour=" + time_text[:13]):
            f.write(sse_trapdoor(K["sse"], word) + "|" + aes_encrypt(K["sse"], voter_id) + "\n")


# ---------- the server side ----------

def server_check(rec, verbose=False):
    """Decrypt, compare SHA-512, verify the signature, check the period.
    Returns (checks dict, ballot text or None)."""
    checks, ballot = {}, None
    try:
        aes_key = bytes.fromhex(rsa_decrypt(K["rsa_priv"], rec["wrapped_key"]))   # 1. unwrap AES key
        ballot = aes_decrypt(aes_key, rec["enc_ballot"])
        recomputed = sha512_hash(ballot)                                           # 2. hash again
        checks["hash"] = recomputed == rec["hash"]
    except Exception:
        recomputed, checks["hash"] = "(decryption failed)", False
    checks["signature"] = elgamal_verify(rec["hash"] + "|" + rec["time"], rec["signature"],
                                         K["eg_p"], K["eg_g"], K["eg_y"])
    checks["period"] = K["start"] <= rec["time"][:16] <= K["end"]                    # 3. voting period
    if verbose:
        show("hash from voter", rec["hash"])
        show("hash recomputed", recomputed)
        for name, flag in checks.items():
            show(name, "OK" if flag else "FAILED")
    return checks, ballot


def search_index(word):
    token = sse_trapdoor(K["sse"], word)
    found = set()
    if os.path.exists(INDEX_FILE):
        with open(INDEX_FILE, encoding="utf-8") as f:
            for line in f:
                stored, enc_id = line.rstrip("\n").split("|")
                if stored == token:
                    found.add(aes_decrypt(K["sse"], enc_id))
    show("search token", token)
    return sorted(found)


# ---------- storage + output helpers ----------

def load_ballots():
    if not os.path.exists(BALLOTS_FILE):
        return []
    with open(BALLOTS_FILE, encoding="utf-8") as f:
        return [dict(zip(FIELDS, line.rstrip("\n").split("|"))) for line in f if line.strip()]


def save_ballots(ballots):
    with open(BALLOTS_FILE, "w", encoding="utf-8") as f:
        for rec in ballots:
            f.write("|".join(rec[k] for k in FIELDS) + "\n")


def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s and "|" not in s and ";" not in s:
            return s
        print("Must be non-empty, without '|' or ';'.")


def section(title):
    print("\n  " + title.upper() + "\n  " + "-" * len(title))


def show(name, value, width=22):
    text = str(value)
    lines = [text[i:i + 64] for i in range(0, len(text), 64)] or [""]
    print("  " + name.ljust(width) + " : " + ("\n" + " " * (width + 5)).join(lines))


def run_menu(title, options):
    while True:
        print("\n--- " + title + " ---")
        for i, (text, _) in enumerate(options, 1):
            print(str(i) + ". " + text)
        print(str(len(options) + 1) + ". Back")
        choice = input("Choice: ").strip()
        if choice == str(len(options) + 1):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            try:
                options[int(choice) - 1][1]()
            except Exception as e:
                print("Error:", type(e).__name__, e)
        else:
            print("Invalid choice.")


# ==================== roles (CHANGE: which role gets which action) ====================

def voter_cast():
    voter_id = ask_text("Voter ID: ")
    if any(r["voter_id"] == voter_id for r in load_ballots()):
        print("This voter has already voted.")
        return None
    print("Candidates: " + ", ".join(str(i) + "=" + c for i, c in enumerate(CANDIDATES, 1)))
    choice = ask_text("Candidate ID: ")
    if not (choice.isdigit() and 1 <= int(choice) <= len(CANDIDATES)):
        print("No such candidate.")
        return None
    candidate = CANDIDATES[int(choice) - 1]
    constituency = ask_text("Constituency ID: ")
    ballot = ballot_text(candidate, constituency)

    section("voter: preparing ballot of " + voter_id)
    rec = {"voter_id": voter_id}
    rec["hash"] = sha512_hash(ballot)                                       # 1
    aes_key = get_random_bytes(32)
    rec["enc_ballot"] = aes_encrypt(aes_key, ballot)                        # 2 AES-256
    rec["wrapped_key"] = rsa_encrypt(K["rsa_pub"], aes_key.hex())           # 3 RSA-4096
    rec["time"] = timestamp()                                               # 6
    rec["signature"] = elgamal_sign(rec["hash"] + "|" + rec["time"], K["eg_p"], K["eg_g"], K["eg_x"])   # 4
    rec["votes"] = encrypt_votes(candidate)                                 # 5 Paillier
    show("ballot", ballot)
    show("SHA-512", rec["hash"])
    show("AES-256 key (hex)", aes_key.hex())
    show("AES ciphertext", rec["enc_ballot"])
    show("RSA-encrypted AES key", rec["wrapped_key"])
    show("ElGamal signature", rec["signature"])
    show("Paillier votes", rec["votes"])
    show("timestamp", rec["time"])

    with open(BALLOTS_FILE, "a", encoding="utf-8") as f:
        f.write("|".join(rec[k] for k in FIELDS) + "\n")
    index_ballot(voter_id, constituency, rec["time"])
    print("  ballot stored in", BALLOTS_FILE)
    return rec


def server_verify_all():
    results = {}
    for rec in load_ballots():
        section("server: checking ballot of " + rec["voter_id"])
        checks, _ = server_check(rec, verbose=True)
        results[rec["voter_id"]] = all(checks.values())
        show("RESULT", "VALID" if results[rec["voter_id"]] else "INVALID")
    return results


def server_search_constituency():
    constituency = ask_text("Constituency ID to search: ")
    ids = search_index("constituency=" + constituency.lower())
    show("ballots found", ids if ids else "none")
    return ids


def server_search_time():
    start = ask_text("From (YYYY-MM-DD HH:MM): ")
    end = ask_text("To   (YYYY-MM-DD HH:MM): ")
    hour = datetime.strptime(start[:13], "%Y-%m-%d %H")
    ids = set()
    while hour <= datetime.strptime(end[:13], "%Y-%m-%d %H"):           # one SSE token per hour
        ids.update(search_index("hour=" + hour.strftime("%Y-%m-%d %H")))
        hour += timedelta(hours=1)
    times = {r["voter_id"]: r["time"][:16] for r in load_ballots()}
    found = sorted(i for i in ids if start <= times[i] <= end)        # exact minutes
    show("ballots in range", found if found else "none")
    return found


def trustees_tally():
    n = K["pa_n"]
    totals = [paillier_encrypt(n, K["pa_g"], 0) for _ in CANDIDATES]
    counted = []
    for rec in load_ballots():
        checks, _ = server_check(rec)
        if not all(checks.values()):
            print("  ", rec["voter_id"], ": INVALID, not counted")
            continue
        for i, c in enumerate(rec["votes"].split(";")):
            totals[i] = paillier_add(n, totals[i], int(c))       # homomorphic addition
        counted.append(rec["voter_id"])
    section("threshold decryption of the totals only")
    results = {}
    for candidate, total in zip(CANDIDATES, totals):
        partials = [threshold_partial_decrypt(n, total, share) for share in K["shares"]]
        for number, partial in enumerate(partials, 1):
            show(candidate + ": trustee " + str(number), str(partial)[:40] + "...")
        results[candidate] = threshold_combine(n, partials)
    show("ballots counted", counted)
    show("RESULT", results)
    return results


def auditor_view():
    for rec in load_ballots():
        section("ballot of " + rec["voter_id"])
        for k in FIELDS:
            show(k, rec[k][:60] + ("..." if len(rec[k]) > 60 else ""))


def tamper():
    voter_id = ask_text("Voter ID to tamper with: ")
    ballots = load_ballots()
    for rec in ballots:
        if rec["voter_id"] == voter_id:
            c = rec["enc_ballot"]
            rec["enc_ballot"] = c[:-1] + ("0" if c[-1] != "0" else "1")
            save_ballots(ballots)
            print("Changed one character of the encrypted ballot.")
            return
    print("Not found.")


def main():
    setup_keys()
    for path in (BALLOTS_FILE, INDEX_FILE):
        if os.path.exists(path):
            os.remove(path)
    while True:
        print("\n===== SECURE E-VOTING =====")
        print("1. Voter\n2. Election Server\n3. Trustee Panel\n4. Auditor\n5. (demo) Tamper\n6. Exit")
        choice = input("Role: ").strip()
        if choice == "1":
            run_menu("Voter", [("Cast ballot", voter_cast)])
        elif choice == "2":
            run_menu("Election Server", [("Verify all ballots", server_verify_all),
                                         ("Search by constituency (SSE)", server_search_constituency),
                                         ("Search by time range (SSE)", server_search_time)])
        elif choice == "3":
            run_menu("Trustee Panel", [("Tally (threshold-decrypt totals only)", trustees_tally)])
        elif choice == "4":
            run_menu("Auditor", [("View stored (encrypted) ballots", auditor_view)])
        elif choice == "5":
            tamper()
        elif choice == "6":
            break


# ---------- self-test: python evoting.py test ----------

def self_test():
    import builtins
    import tempfile
    global BALLOTS_FILE, INDEX_FILE
    tmp = tempfile.mkdtemp()
    BALLOTS_FILE, INDEX_FILE = os.path.join(tmp, "b.txt"), os.path.join(tmp, "i.txt")
    queue = []
    builtins.input = lambda prompt="": (print(prompt + queue[0]) or queue.pop(0))

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()

    setup_keys()
    run(voter_cast, "V1", "1", "C1")
    run(voter_cast, "V2", "2", "C2")
    run(voter_cast, "V3", "1", "C1")
    assert run(voter_cast, "V1") is None                       # cannot vote twice
    assert run(server_verify_all) == {"V1": True, "V2": True, "V3": True}
    assert run(server_search_constituency, "C1") == ["V1", "V3"]
    hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
    later = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
    assert run(server_search_time, hour_ago, later) == ["V1", "V2", "V3"]
    assert run(trustees_tally) == {"Alice": 2, "Bob": 1, "Carol": 0}
    run(auditor_view)
    run(tamper, "V2")
    assert run(trustees_tally) == {"Alice": 2, "Bob": 0, "Carol": 0}   # tampered ballot not counted
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
