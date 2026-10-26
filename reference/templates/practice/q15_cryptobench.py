# =============================================================================
# PRACTICE QUESTION (from guide/practice_questions.py)
#
# Q15 CryptoBench -- performance comparison                      (labs 2, 3, 7)
#  Encrypt 1 KB / 10 KB / 100 KB messages with DES, AES-128, AES-256,
#  RSA-hybrid and ECC; time key generation, encryption, decryption; print a
#  table and say which is fastest. Lab 7 variant: Paillier vs ElGamal vs RSA
#  homomorphic operations on 100 numbers.
#
# Hand-written template (timing comparison is not a generator shape).
# Run:  python q15_cryptobench.py      python q15_cryptobench.py test
# =============================================================================

import math
import random
import sys
import time
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, getRandomRange
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------- from ciphers/block_modes.py (verbatim) ----------

ALGORITHMS = {"aes": AES, "des": DES}


PADDED_MODES = ("ecb", "cbc")


def _to_bytes(value):
    return value.encode() if isinstance(value, str) else value


def _new_cipher(algorithm, mode, key, iv):
    module = ALGORITHMS[algorithm]
    mode_constant = getattr(module, "MODE_" + mode.upper())

    if mode == "ecb":
        return module.new(key, mode_constant)
    if mode == "ctr":
        return module.new(key, mode_constant, nonce=iv)
    return module.new(key, mode_constant, iv)


def block_encrypt(algorithm, mode, key, plaintext, iv=None):
    algorithm, mode = algorithm.lower(), mode.lower()
    module = ALGORITHMS[algorithm]
    data = plaintext.encode()

    if mode == "ecb":
        iv = b""
    else:
        iv_size = module.block_size // 2 if mode == "ctr" else module.block_size
        iv = _to_bytes(iv) if iv is not None else get_random_bytes(iv_size)
        if len(iv) != iv_size:
            raise ValueError(f"{algorithm} {mode}: iv/nonce must be {iv_size} bytes, got {len(iv)}")

    cipher = _new_cipher(algorithm, mode, _to_bytes(key), iv)
    if mode in PADDED_MODES:
        data = pad(data, module.block_size)

    return (iv + cipher.encrypt(data)).hex()


def block_decrypt(algorithm, mode, key, ciphertext):
    algorithm, mode = algorithm.lower(), mode.lower()
    module = ALGORITHMS[algorithm]
    raw = bytes.fromhex(ciphertext)

    if mode == "ecb":
        iv, encrypted = b"", raw
    else:
        iv_size = module.block_size // 2 if mode == "ctr" else module.block_size
        iv, encrypted = raw[:iv_size], raw[iv_size:]

    cipher = _new_cipher(algorithm, mode, _to_bytes(key), iv)   # a fresh cipher object
    data = cipher.decrypt(encrypted)
    if mode in PADDED_MODES:
        data = unpad(data, module.block_size)

    return data.decode()


# ---------- from ciphers/aes.py (verbatim) ----------

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


# ---------- from ciphers/rsa.py (verbatim) ----------

def rsa_generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
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


# ---------- from ciphers/ecc.py (verbatim) ----------

def ecc_generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"ecc encryption"
    ).derive(shared_secret)


def ecc_encrypt(public_key, plaintext):
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    aes_key = derive_shared_key(ephemeral_key, public_key)

    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    ephemeral_public_bytes = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )

    return (ephemeral_public_bytes + iv + encrypted).hex()


def ecc_decrypt(private_key, ciphertext):
    raw = bytes.fromhex(ciphertext)

    ephemeral_public_bytes = raw[:65]
    iv = raw[65:65 + AES.block_size]
    encrypted = raw[65 + AES.block_size:]

    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_public_bytes
    )
    aes_key = derive_shared_key(private_key, ephemeral_public_key)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted.decode()


# ---------- from ciphers/paillier.py (verbatim) ----------

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


def paillier_add(n, c1, c2):
    return (c1 * c2) % (n * n)


# ---------- from ciphers/rsa_homomorphic.py (verbatim) ----------

def rsa_he_generate_keys(bits=1024):
    e = 65537

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(e, phi) == 1:
            break

    d = pow(e, -1, phi)

    return p * q, e, d


def rsa_he_encrypt(n, e, message):
    return pow(message, e, n)


def rsa_he_decrypt(n, d, ciphertext):
    return pow(ciphertext, d, n)


def rsa_he_multiply(n, c1, c2):
    return (c1 * c2) % n


# ---------- from ciphers/elgamal_homomorphic.py (verbatim) ----------

def elgamal_he_generate_keys(bits=512):
    p = getPrime(bits)
    g = 2
    x = getRandomRange(2, p - 1)   # private key
    h = pow(g, x, p)               # public key

    return p, g, h, x


def elgamal_he_encrypt(p, g, h, m):
    k = getRandomRange(2, p - 1)

    return pow(g, k, p), (m * pow(h, k, p)) % p


def elgamal_he_decrypt(p, x, ciphertext):
    c1, c2 = ciphertext
    s = pow(c1, x, p)

    return (c2 * pow(s, -1, p)) % p


def elgamal_he_multiply(p, ct1, ct2):
    return (ct1[0] * ct2[0]) % p, (ct1[1] * ct2[1]) % p


# ==================== CHANGE: what to measure ====================

SIZES = [1024, 10 * 1024, 100 * 1024]      # CHANGE: message sizes in bytes (1 KB, 10 KB, 100 KB)
HE_COUNT = 100                             # CHANGE: how many numbers for the homomorphic part


def timed(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    return result, (time.perf_counter() - start) * 1000      # ms


# ---------- each algorithm: (key generation, encrypt, decrypt) ----------

def bench_des(message):
    key, t_key = timed(get_random_bytes, 8)
    c, t_enc = timed(block_encrypt, "des", "cbc", key, message)
    m, t_dec = timed(block_decrypt, "des", "cbc", key, c)
    return t_key, t_enc, t_dec, m == message


def bench_aes(size):
    def run_aes(message):
        key, t_key = timed(get_random_bytes, size)
        c, t_enc = timed(aes_encrypt, key, message)
        m, t_dec = timed(aes_decrypt, key, c)
        return t_key, t_enc, t_dec, m == message
    return run_aes


def bench_rsa_hybrid(message):
    """RSA cannot encrypt 100 KB directly: AES-256 encrypts the data, RSA encrypts the AES key."""
    (private, public, n, e, d), t_key = timed(rsa_generate_keys)
    start = time.perf_counter()
    aes_key = get_random_bytes(32)
    c, wrapped = aes_encrypt(aes_key, message), rsa_encrypt(public, aes_key.hex())
    t_enc = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    m = aes_decrypt(bytes.fromhex(rsa_decrypt(private, wrapped)), c)
    t_dec = (time.perf_counter() - start) * 1000
    return t_key, t_enc, t_dec, m == message


def bench_ecc(message):
    (private, public), t_key = timed(ecc_generate_keys)
    c, t_enc = timed(ecc_encrypt, public, message)
    m, t_dec = timed(ecc_decrypt, private, c)
    return t_key, t_enc, t_dec, m == message


ALGORITHMS_TO_TEST = [("DES-CBC", bench_des), ("AES-128", bench_aes(16)), ("AES-256", bench_aes(32)),
                      ("RSA-2048 hybrid", bench_rsa_hybrid), ("ECC (ECIES)", bench_ecc)]     # CHANGE: add / remove


def symmetric_table(sizes):
    results = {}
    for size in sizes:
        message = "".join(random.choice("abcdefghijklmnopqrstuvwxyz ") for _ in range(size))
        print("\n  message size: %d bytes" % size)
        print("  %-16s %10s %10s %10s  %s" % ("algorithm", "keygen ms", "encrypt ms", "decrypt ms", "correct"))
        rows = []
        for name, bench in ALGORITHMS_TO_TEST:
            t_key, t_enc, t_dec, ok = bench(message)
            rows.append((name, t_enc + t_dec, ok))
            print("  %-16s %10.2f %10.2f %10.2f  %s" % (name, t_key, t_enc, t_dec, ok))
        fastest = min(rows, key=lambda r: r[1])[0]
        print("  fastest (encrypt + decrypt):", fastest)
        results[size] = rows
    return results


def homomorphic_table(count):
    numbers = [random.randint(1, 3) for _ in range(count)]     # small, so the product stays below n
    print("\n  homomorphic operations on %d numbers" % count)
    print("  %-26s %10s %10s %10s  %s" % ("scheme", "keygen ms", "encrypt ms", "combine+dec", "correct"))
    rows = []

    (n, g, lam, mu), t_key = timed(paillier_generate_keys, 1024)
    cs, t_enc = timed(lambda: [paillier_encrypt(n, g, x) for x in numbers])
    start = time.perf_counter()
    total = cs[0]
    for c in cs[1:]:
        total = paillier_add(n, total, c)
    value = paillier_decrypt(n, lam, mu, total)
    rows.append(("Paillier SUM", t_key, t_enc, (time.perf_counter() - start) * 1000, value == sum(numbers)))

    (rn, re_, rd), t_key = timed(rsa_he_generate_keys, 1024)
    cs, t_enc = timed(lambda: [rsa_he_encrypt(rn, re_, x) for x in numbers])
    start = time.perf_counter()
    total = cs[0]
    for c in cs[1:]:
        total = rsa_he_multiply(rn, total, c)
    product = 1
    for x in numbers:
        product *= x
    value = rsa_he_decrypt(rn, rd, total)
    rows.append(("textbook RSA PRODUCT", t_key, t_enc, (time.perf_counter() - start) * 1000, value == product))

    (p, eg, h, x), t_key = timed(elgamal_he_generate_keys, 512)
    cs, t_enc = timed(lambda: [elgamal_he_encrypt(p, eg, h, v) for v in numbers])
    start = time.perf_counter()
    total = cs[0]
    for c in cs[1:]:
        total = elgamal_he_multiply(p, total, c)
    value = elgamal_he_decrypt(p, x, total)
    rows.append(("ElGamal PRODUCT", t_key, t_enc, (time.perf_counter() - start) * 1000, value == product % p))

    for name, t_key, t_enc, t_rest, ok in rows:
        print("  %-26s %10.2f %10.2f %10.2f  %s" % (name, t_key, t_enc, t_rest, ok))
    return rows


def main():
    symmetric_table(SIZES)
    homomorphic_table(HE_COUNT)


def self_test():
    results = symmetric_table([256, 2048])
    assert all(ok for rows in results.values() for _, _, ok in rows)
    assert all(row[-1] for row in homomorphic_table(20))
    print("\nSELF-TEST PASSED")


if __name__ == "__main__":
    self_test() if len(sys.argv) > 1 and sys.argv[1] == "test" else main()
