# Secure medical diagnosis on ENCRYPTED blood pressure: is it above 130, without
# anyone decrypting the reading itself.
#
# The manual asks for this with ElGamal, but ElGamal only multiplies -- it has no
# way to compare two numbers (the manual's snippet cannot work: its key loop
# never ends and its "comparison" is not a comparison). Paillier can do it
# because it can SUBTRACT:
#
#   Enc(reading)  ->  Enc(reading - 130)  ->  Enc((reading - 130) * r)    r random > 0
#
# The clinic server does these steps with the PUBLIC key only. The doctor
# decrypts just the final blinded number: its SIGN says high / not high, and r
# hides the size, so the reading is never revealed.
# (Demonstration blinding -- a real system would use a proper secure-comparison
# protocol.)

import math
from Crypto.Util.number import getPrime, getRandomRange


# ---- from ciphers/paillier.py (verbatim) ----

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


def paillier_decrypt(n, lam, mu, ciphertext):
    l = (pow(ciphertext, lam, n * n) - 1) // n

    return (l * mu) % n


def paillier_add_plain(n, g, ciphertext, k):
    return (ciphertext * pow(g, k % n, n * n)) % (n * n)


def paillier_multiply_plain(n, ciphertext, k):
    return pow(ciphertext, k, n * n)


# ---------- the diagnosis ----------

THRESHOLD = 130


def encrypted_excess(n, g, encrypted_reading, threshold=THRESHOLD):
    """Clinic server (public key only): Enc(reading) -> Enc((reading - threshold) * r)."""
    difference = paillier_add_plain(n, g, encrypted_reading, -threshold)

    return paillier_multiply_plain(n, difference, getRandomRange(1, 2 ** 64))


def blinded_value(n, lam, mu, blinded):
    """Doctor (private key): the decrypted number, read as signed."""
    value = paillier_decrypt(n, lam, mu, blinded)

    return value - n if value > n // 2 else value


def diagnosis(value):
    return "High Blood Pressure detected." if value > 0 else "Normal Blood Pressure."


if __name__ == "__main__":
    n, g, lam, mu = paillier_generate_keys(512)       # the doctor's keys

    readings = {"Asha": 120, "Ravi": 140, "Meera": 130, "Kiran": 155}

    print(f"{'Patient':<8} {'blinded value the doctor sees':<34} Diagnosis")
    for name, reading in readings.items():
        encrypted_reading = paillier_encrypt(n, g, reading)                 # patient device
        blinded = encrypted_excess(n, g, encrypted_reading)                 # clinic server
        value = blinded_value(n, lam, mu, blinded)                          # doctor

        print(f"{name:<8} {str(value)[:30]:<34} {diagnosis(value)}")
        assert (value > 0) == (reading > THRESHOLD)

    print("\nThe doctor never saw a reading; 130 itself counts as normal (high means > 130).")
