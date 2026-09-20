# Breaking additive / multiplicative / affine ciphers.
#
#   Know a plaintext/ciphertext pair -> solve for the key directly.
#   Know nothing                     -> try every key (only 26 additive keys,
#                                       12 multiplicative, 312 affine) and read
#                                       off the candidate that is English.
#
# Non-letters in the ciphertext (spaces, "/", "&") are dropped, like the
# encrypt functions in ciphers/primitives.py do.

import string

A = string.ascii_lowercase
VALID_MULTIPLIERS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]   # coprime with 26


def _letters(text):
    return ''.join(c for c in text.lower() if c.isalpha())


# ---------- additive ----------

def additive_key_from_pair(cipher_char, plain_char):
    """C = (P + key) mod 26  =>  key = (C - P) mod 26"""
    return (A.index(cipher_char.lower()) - A.index(plain_char.lower())) % 26


def brute_force_additive(ciphertext):
    """[(key, decrypted text)] for all 26 keys."""
    ciphertext = _letters(ciphertext)
    return [(key, ''.join(A[(A.index(c) - key) % 26] for c in ciphertext))
            for key in range(26)]


# ---------- multiplicative ----------

def brute_force_multiplicative(ciphertext):
    """[(key, decrypted text)] for the 12 keys that have an inverse mod 26."""
    ciphertext = _letters(ciphertext)
    results = []
    for key in VALID_MULTIPLIERS:
        inverse = pow(key, -1, 26)
        results.append((key, ''.join(A[(A.index(c) * inverse) % 26] for c in ciphertext)))
    return results


# ---------- affine:  C = (a*P + b) mod 26 ----------

def brute_force_affine(ciphertext, known_plain, known_cipher):
    """[((a, b), decrypted text)] for every (a, b) that turns known_plain into
    known_cipher. With a two-letter known pair there is normally exactly one."""
    ciphertext = _letters(ciphertext)
    known_plain, known_cipher = _letters(known_plain), _letters(known_cipher)
    results = []

    for a in VALID_MULTIPLIERS:
        for b in range(26):
            encrypted = ''.join(A[(a * A.index(p) + b) % 26] for p in known_plain)
            if encrypted == known_cipher:
                inverse = pow(a, -1, 26)
                decrypted = ''.join(A[(inverse * (A.index(c) - b)) % 26] for c in ciphertext)
                results.append(((a, b), decrypted))

    return results


def print_candidates(candidates):
    for key, text in candidates:
        print(f"key={key!s:>8}: {text}")


if __name__ == "__main__":
    # Known pair: "yes" was enciphered as "CIW" with a shift cipher
    print("key from a known pair:", additive_key_from_pair("c", "y"))

    # Brute force an additive cipher (the manual's exercise: the key is near 13)
    print("\nadditive, keys 11-13 only (key 11 is the English one):")
    print_candidates(brute_force_additive("NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY")[11:14])

    # Affine: plaintext "ab" was enciphered to "GL" (the manual's exercise)
    print("\naffine with known pair ab -> GL:")
    print_candidates(brute_force_affine("XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS", "ab", "GL"))

    # round-trip check of the multiplicative search
    from_mult = ''.join(A[(A.index(c) * 7) % 26] for c in "attackatdawn")
    assert (7, "attackatdawn") in brute_force_multiplicative(from_mult)
    print("\nmultiplicative brute force recovers the key: OK")
