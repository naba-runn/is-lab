# =============================================================================
# PRACTICE QUESTION (from guide/practice_questions.py)
#
# Q12 MilitaryRelay -- DH + affine / Vigenere field messages      (labs 1, 3)
#  HQ and Unit agree on a Diffie-Hellman key with p = 467, g = 2, private
#  keys given. Message is cleaned to A-Z.
#  Variant A: affine with k1 typed (gcd check, inverse shown), k2 = K mod 26.
#  Variant B: Vigenere with the key word made from the digits of K
#    (0 -> A, 1 -> B, ...).
#  Variant C: Hill 2x2 with a key matrix derived from K, check invertibility
#    mod 26.
#
# Hand-written template (the generator's key-exchange mode has affine only).
# Run:  python q12_militaryrelay.py      python q12_militaryrelay.py test
# =============================================================================

import math
import string
import sys
from Crypto.Util.number import getRandomRange


# ---------- from ciphers/dh.py (verbatim) ----------

def dh_generate_keypair(p, g):
    private_key = getRandomRange(2, p - 1)
    public_key = pow(g, private_key, p)

    return public_key, private_key


def compute_shared_secret(their_public_key, my_private_key, p):
    return pow(their_public_key, my_private_key, p)


# ---------- from ciphers/primitives.py (verbatim) ----------

A = string.ascii_lowercase


def affine_encrypt(text, a, b):
    return ''.join(A[(a * A.index(c) + b) % 26]
                   for c in text.lower() if c.isalpha())


def affine_decrypt(text, a, b):
    inv = pow(a, -1, 26)
    return ''.join(A[(inv * (A.index(c) - b)) % 26]
                   for c in text.lower() if c.isalpha())


# ---------- from ciphers/vigenere.py (verbatim) ----------

def vigenere_encrypt(text, key):
    text = ''.join(c for c in text.lower() if c.isalpha())
    key = ''.join(c for c in key.lower() if c.isalpha())

    return ''.join(
        A[(A.index(c) + A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(text)
    )


def vigenere_decrypt(cipher, key):
    cipher = ''.join(c for c in cipher.lower() if c.isalpha())
    key = ''.join(c for c in key.lower() if c.isalpha())

    return ''.join(
        A[(A.index(c) - A.index(key[i % len(key)])) % 26]
        for i, c in enumerate(cipher)
    )


# ---------- from ciphers/hill.py (verbatim) ----------

def hill_encrypt(text, K):
    text = ''.join(c for c in text.lower() if c.isalpha())

    # Padding
    if len(text) % 2 != 0:
        text += 'x'

    cipher = ""

    for i in range(0, len(text), 2):

        x1 = A.index(text[i])
        x2 = A.index(text[i + 1])

        y1 = (K[0][0] * x1 + K[0][1] * x2) % 26
        y2 = (K[1][0] * x1 + K[1][1] * x2) % 26

        cipher += A[y1] + A[y2]

    return cipher


def hill_decrypt(cipher, K):
    cipher = ''.join(c for c in cipher.lower() if c.isalpha())

    det = (K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26
    det_inv = pow(det, -1, 26)

    inv_K = [
        [(K[1][1] * det_inv) % 26, (-K[0][1] * det_inv) % 26],
        [(-K[1][0] * det_inv) % 26, (K[0][0] * det_inv) % 26],
    ]

    plaintext = ""

    for i in range(0, len(cipher), 2):

        y1 = A.index(cipher[i])
        y2 = A.index(cipher[i + 1])

        x1 = (inv_K[0][0] * y1 + inv_K[0][1] * y2) % 26
        x2 = (inv_K[1][0] * y1 + inv_K[1][1] * y2) % 26

        plaintext += A[x1] + A[x2]

    return plaintext


# ==================== CHANGE: the numbers given in the question ====================

P = 467                    # CHANGE: DH prime p
G = 2                      # CHANGE: DH generator g
HQ_PRIVATE = 153           # CHANGE: HQ's private key   (None -> random)
UNIT_PRIVATE = 197         # CHANGE: Unit's private key (None -> random)


# ---------- input / output helpers ----------

def ask_text(prompt):
    while True:
        s = input(prompt).strip()
        if s:
            return s
        print("Please type something.")


def section(title):
    print("\n  " + title.upper() + "\n  " + "-" * len(title))


def show(name, value, width=24):
    text = str(value)
    lines = [text[i:i + 64] for i in range(0, len(text), 64)] or [""]
    print("  " + name.ljust(width) + " : " + ("\n" + " " * (width + 5)).join(lines))


def run_menu(title, options):
    while True:
        print("\n--- " + title + " ---")
        for i, (text, _) in enumerate(options, 1):
            print(str(i) + ". " + text)
        print(str(len(options) + 1) + ". Exit")
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


# ---------- key exchange ----------

def keypair(given):
    """(public, private): the given private key, or a random one."""
    if given is not None:
        return pow(G, given, P), given
    return dh_generate_keypair(P, G)


def key_exchange():
    section("Diffie-Hellman")
    show("p, g", (P, G))
    hq_public, a = keypair(HQ_PRIVATE)
    unit_public, b = keypair(UNIT_PRIVATE)
    show("HQ   private a / public A", (a, hq_public))
    show("Unit private b / public B", (b, unit_public))
    hq_k = compute_shared_secret(unit_public, a, P)
    unit_k = compute_shared_secret(hq_public, b, P)
    show("HQ   K = B^a mod p", hq_k)
    show("Unit K = A^b mod p", unit_k)
    if hq_k != unit_k:
        print("  FAILURE: the shared secrets differ.")
        return None
    print("  shared secrets match")
    return hq_k


def clean(text):
    return "".join(c for c in text.lower() if c in A)


# ---------- the three variants: key material from K ----------

def ask_k1():
    """Affine k1: asked until gcd(k1, 26) = 1; invalid values are discarded."""
    while True:
        s = input("k1 (gcd(k1, 26) must be 1): ").strip()
        if not s.lstrip("-").isdigit():
            print("  INVALID: k1 must be a whole number -- discarded.")
            continue
        k1 = int(s)
        if math.gcd(k1, 26) != 1:
            print("  INVALID: gcd(" + str(k1) + ", 26) =", math.gcd(k1, 26), "-> discarded.")
            continue
        show("k1 accepted, inverse mod 26", pow(k1, -1, 26))
        return k1


def vigenere_key(k):
    """Digits of K as letters: 0 -> a, 1 -> b, ... (CHANGE if the question says otherwise)."""
    return "".join(A[int(d)] for d in str(k))


def hill_key(k):
    """2x2 matrix from K in base 26; bumped until it is invertible mod 26."""
    m = [[k % 26, (k // 26) % 26], [(k // 676) % 26, (k // 17576) % 26]]
    while math.gcd((m[0][0] * m[1][1] - m[0][1] * m[1][0]) % 26, 26) != 1:
        print("  matrix", m, "is not invertible mod 26 -> adding 1 to the bottom-right entry")
        m[1][1] = (m[1][1] + 1) % 26
    show("Hill key matrix", m)
    show("determinant mod 26", (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % 26)
    return m


def relay(variant, k, message):
    """HQ encrypts, the Unit decrypts with its own copy of K. Returns the decrypted text."""
    text = clean(message)
    if not text:
        print("  FAILURE: no letters in the message.")
        return None
    section("variant " + variant)
    show("plaintext (letters only)", text)
    if variant == "affine":
        k1, k2 = ask_k1(), k % 26
        show("k2 = K mod 26", k2)
        ciphertext = affine_encrypt(text, k1, k2)
        received = affine_decrypt(ciphertext, k1, k2)
    elif variant == "vigenere":
        key = vigenere_key(k)
        show("Vigenere key from K", key)
        ciphertext = vigenere_encrypt(text, key)
        received = vigenere_decrypt(ciphertext, key)
    else:
        m = hill_key(k)
        ciphertext = hill_encrypt(text, m)
        received = hill_decrypt(ciphertext, m)
    show("HQ ciphertext", ciphertext.upper())
    show("Unit decrypts", received.upper())
    ok = received.startswith(text)          # Hill may add one padding 'x'
    print("  SUCCESS: Unit recovered the message." if ok else "  FAILURE: texts differ.")
    return received


def main():
    k = key_exchange()
    if k is None:
        return
    run_menu("MilitaryRelay: choose the cipher", [
        ("Affine (k1 typed, k2 = K mod 26)", lambda: relay("affine", k, ask_text("Message: "))),
        ("Vigenere (key = digits of K as letters)", lambda: relay("vigenere", k, ask_text("Message: "))),
        ("Hill 2x2 (matrix from K)", lambda: relay("hill", k, ask_text("Message: "))),
    ])


def self_test():
    import builtins
    queue = []

    def fake_input(prompt=""):
        answer = queue.pop(0)
        print(prompt + answer)
        return answer

    builtins.input = fake_input

    def run(fn, *answers):
        queue[:] = list(answers)
        return fn()
    k = key_exchange()
    assert k == pow(G, HQ_PRIVATE * UNIT_PRIVATE, P)
    message = "Attack at dawn, sector 7!"
    assert run(lambda: relay("affine", k, message), "13", "x", "5") == "attackatdawnsector"
    assert run(lambda: relay("vigenere", k, message)) == "attackatdawnsector"
    assert run(lambda: relay("hill", k, message)).startswith("attackatdawnsector")
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
