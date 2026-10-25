# FieldTrack -- exam TEMPLATE
#
# QUESTION
#   Sender and Receiver establish a Diffie-Hellman shared secret K with the
#   given parameters and check both secrets are equal.
#   Plaintext -> UPPERCASE, keep A-Z only.
#   k2 is given (2). Check K mod 26 == k2, then ask for k1, check
#   gcd(k1, 26) == 1 and compute the inverse of k1.
#   Affine-encrypt (C = k1*P + k2 mod 26); the Receiver repeats the same
#   checks and decrypts (P = k1^-1 * (C - k2) mod 26). An invalid k1 is
#   discarded; every failure prints a clear message.
#
# HOW TO ADAPT -- search for "CHANGE:"
#   - P, G, the two private keys (None = random), K2
#   - another cipher after DH? replace affine_encrypt / affine_decrypt
#
# Run:  python fieldtrack.py         python fieldtrack.py test

import math
import string
import sys
from Crypto.Util.number import getRandomRange


# ---- from ciphers/dh.py (verbatim) ----

def dh_generate_keypair(p, g):
    private_key = getRandomRange(2, p - 1)
    public_key = pow(g, private_key, p)

    return public_key, private_key      # (public, private) like every generator


def compute_shared_secret(their_public_key, my_private_key, p):
    return pow(their_public_key, my_private_key, p)


# ---- adapted from ciphers/primitives.py: UPPERCASE alphabet, input already cleaned to A-Z ----

A = string.ascii_uppercase


def affine_encrypt(text, a, b):
    return "".join(A[(a * A.index(c) + b) % 26] for c in text)


def affine_decrypt(text, a, b):
    inv = pow(a, -1, 26)
    return "".join(A[(inv * (A.index(c) - b)) % 26] for c in text)


# ==================== CHANGE: the numbers given in the question ====================

P = 23                     # CHANGE: DH prime p
G = 5                      # CHANGE: DH generator g
SENDER_PRIVATE = 6         # CHANGE: sender's private key a   (None -> random)
RECEIVER_PRIVATE = 15      # CHANGE: receiver's private key b (None -> random)
K2 = 2                     # CHANGE: k2 given in the question


def clean(text):
    """Uppercase, keep A-Z only."""
    return "".join(c for c in text.upper() if c in A)


def keypair(given):
    """(public, private) -- the given private key, or a random one."""
    if given is not None:
        return pow(G, given, P), given
    return dh_generate_keypair(P, G)


def key_exchange():
    print("Public parameters: p =", P, " g =", G)
    sender_public, a = keypair(SENDER_PRIVATE)
    receiver_public, b = keypair(RECEIVER_PRIVATE)
    print("Sender   : private a =", a, "  public A = g^a mod p =", sender_public)
    print("Receiver : private b =", b, "  public B = g^b mod p =", receiver_public)
    sender_k = compute_shared_secret(receiver_public, a, P)      # B^a mod p
    receiver_k = compute_shared_secret(sender_public, b, P)      # A^b mod p
    print("Sender   computes K = B^a mod p =", sender_k)
    print("Receiver computes K = A^b mod p =", receiver_k)
    if sender_k != receiver_k:
        print("FAILURE: the shared secrets differ -- stopping.")
        return None, None
    print("Shared secrets match: K =", sender_k)
    return sender_k, receiver_k


def check_k2(who, k):
    print(who + ": K mod 26 =", k % 26, "  k2 =", K2)
    if k % 26 != K2:
        print("  FAILURE: K mod 26 != k2 -- keys do not match, stopping.")
        return False
    print("  K mod 26 == k2 -> OK")
    return True


def ask_k1(who):
    """Asks until k1 is valid; an invalid k1 is discarded with a message."""
    while True:
        s = input(who + ": enter k1 (gcd(k1, 26) must be 1): ").strip()
        try:
            k1 = int(s)
        except ValueError:
            print("  INVALID: k1 must be a whole number -- discarded.")
            continue
        if math.gcd(k1, 26) != 1:
            print("  INVALID: gcd(" + str(k1) + ", 26) =", math.gcd(k1, 26), "-> no inverse mod 26, k1 discarded.")
            continue
        inverse = pow(k1, -1, 26)
        print("  k1 =", k1, "accepted. Inverse of k1 mod 26 =", inverse,
              "(check:", k1, "*", inverse, "mod 26 =", (k1 * inverse) % 26, ")")
        return k1


def sender_side(k):
    print("\n--- SENDER ---")
    if not check_k2("Sender", k):
        return None
    k1 = ask_k1("Sender")
    text = clean(input("Sender: message: "))
    if not text:
        print("  FAILURE: no letters A-Z in the message -- nothing to encrypt.")
        return None
    ciphertext = affine_encrypt(text, k1, K2)
    print("  plaintext (A-Z only):", text)
    print("  ciphertext          :", ciphertext)
    return text, ciphertext


def receiver_side(k, ciphertext):
    print("\n--- RECEIVER ---")
    if not check_k2("Receiver", k):
        return None
    k1 = ask_k1("Receiver")
    plaintext = affine_decrypt(ciphertext, k1, K2)
    print("  decrypted plaintext :", plaintext)
    return plaintext


def main():
    sender_k, receiver_k = key_exchange()
    if sender_k is None:
        return None
    sent = sender_side(sender_k)
    if sent is None:
        return None
    plaintext, ciphertext = sent
    received = receiver_side(receiver_k, ciphertext)
    if received is None:
        return None
    if received == plaintext:
        print("\nSUCCESS: the Receiver recovered exactly the Sender's message.")
    else:
        print("\nFAILURE: decrypted text differs (did the Receiver use a different k1?).")
    return received


def self_test():
    import builtins
    queue = ["13", "abc", "5", "Field team at grid 7, move north!", "4", "5"]   # two bad k1 values first
    builtins.input = lambda prompt="": (print(prompt + queue[0]) or queue.pop(0))
    assert main() == "FIELDTEAMATGRIDMOVENORTH"
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
