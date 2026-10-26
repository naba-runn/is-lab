# =============================================================================
# PRACTICE QUESTION (from guide/practice_questions.py)
#
# Q16 ClassicTrack -- chained classical ciphers                     (lab 1)
#  Encrypt "the house is being sold tonight" with Playfair (key "guidance"),
#  then Vigenere (key "dollars"), then decrypt in reverse. (Playfair first:
#  it turns j into i and adds filler x's, so it cannot sit in the MIDDLE of a
#  chain that must decrypt back exactly.) Then brute-force an additive cipher
#  ciphertext and find the key from a known word.
#
# Hand-written template (classical chain + brute force).
# Run:  python q16_classictrack.py      python q16_classictrack.py test
# =============================================================================

import string
import sys


# ---------- from ciphers/playfair.py (verbatim) ----------

def create_matrix(key):
    key = key.lower().replace('j', 'i')
    alphabet = "abcdefghijklmnopqrstuvwxyz"

    chars = ""

    for c in key + alphabet:
        if c == 'j':
            c = 'i'
        if c not in chars:
            chars += c

    return [chars[i:i+5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = ''.join(c for c in text.lower() if c.isalpha())
    text = text.replace('j', 'i')

    pairs = []
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 == len(text):
            pairs.append(a + 'x')
            i += 1

        elif text[i + 1] == a:
            pairs.append(a + 'x')
            i += 1

        else:
            pairs.append(a + text[i + 1])
            i += 2

    return pairs


def playfair_encrypt(text, key):
    matrix = create_matrix(key)

    position = {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }

    result = ""

    for a, b in prepare_text(text):

        r1, c1 = position[a]
        r2, c2 = position[b]

        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]

        # Same column
        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]

        # Rectangle
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def playfair_decrypt(cipher, key):
    matrix = create_matrix(key)

    position = {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }

    cipher = ''.join(c for c in cipher.lower() if c.isalpha())

    result = ""

    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i + 1]

        r1, c1 = position[a]
        r2, c2 = position[b]

        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        # Same column
        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        # Rectangle
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


# ---------- from ciphers/vigenere.py (verbatim) ----------

A = string.ascii_lowercase


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


# ---------- from ciphers/primitives.py (verbatim) ----------

def additive_encrypt(text, key):
    return ''.join(A[(A.index(c) + key) % 26]
                   for c in text.lower() if c.isalpha())


def additive_decrypt(text, key):
    return ''.join(A[(A.index(c) - key) % 26]
                   for c in text.lower() if c.isalpha())


# ==================== CHANGE: texts and keys from the question ====================

MESSAGE = "the house is being sold tonight"     # CHANGE
PLAYFAIR_KEY = "guidance"                       # CHANGE
VIGENERE_KEY = "dollars"                        # CHANGE

BRUTE_PLAINTEXT = "meet me at the usual place at ten"   # CHANGE: (or paste the given ciphertext below)
BRUTE_SECRET_KEY = 7                                     # CHANGE
KNOWN_WORD = "usual"                                     # CHANGE: a word known to be in the plaintext


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


def chain(message, playfair_key, vigenere_key):
    section("encrypt: Playfair then Vigenere")
    show("plaintext", message)
    show("Playfair pairs", " ".join(prepare_text(message)))
    for row in create_matrix(playfair_key):
        print("    " + " ".join(row))
    step1 = playfair_encrypt(message, playfair_key)
    show("after Playfair", step1)
    step2 = vigenere_encrypt(step1, vigenere_key)
    show("after Vigenere", step2)

    section("decrypt in reverse: Vigenere then Playfair")
    back1 = vigenere_decrypt(step2, vigenere_key)
    show("Vigenere decrypted", back1)
    back2 = playfair_decrypt(back1, playfair_key)
    show("Playfair decrypted", back2)
    show("(original, prepared)", "".join(prepare_text(message)))
    print("  Playfair keeps its filler x's and turns j into i -- that is the only difference.")
    return step2, back2


def brute_force(ciphertext, known_word):
    section("brute force: additive cipher")
    show("ciphertext", ciphertext)
    found = None
    for key in range(26):
        candidate = additive_decrypt(ciphertext, key)
        mark = "  <-- contains '" + known_word + "'" if known_word in candidate else ""
        print("  key %2d : %s%s" % (key, candidate, mark))
        if mark and found is None:
            found = key
    show("key found", found)
    return found


def main():
    chain(MESSAGE, PLAYFAIR_KEY, VIGENERE_KEY)
    brute_force(additive_encrypt(BRUTE_PLAINTEXT, BRUTE_SECRET_KEY), KNOWN_WORD)


def self_test():
    _, back = chain(MESSAGE, PLAYFAIR_KEY, VIGENERE_KEY)
    assert back == "".join(prepare_text(MESSAGE))
    assert brute_force(additive_encrypt(BRUTE_PLAINTEXT, BRUTE_SECRET_KEY), KNOWN_WORD) == BRUTE_SECRET_KEY
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
