import time
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ---------- Rabin cryptosystem ----------

def _prime_3_mod_4(bits):
    """p, q must be = 3 (mod 4) so decryption can extract square roots directly."""
    while True:
        p = getPrime(bits)
        if p % 4 == 3:
            return p


def rabin_generate_keys(bits=1024):
    p = _prime_3_mod_4(bits // 2)
    q = _prime_3_mod_4(bits // 2)
    n = p * q     # public key

    return n, (p, q)   # (public key, private key)


def rabin_encrypt(n, plaintext):
    return ",".join(str(pow(ord(ch), 2, n)) for ch in plaintext)


def rabin_decrypt(n, p, q, ciphertext, alphabet_size=256):
    plaintext = ""

    for part in ciphertext.split(","):
        c = int(part)

        mp = pow(c, (p + 1) // 4, p)
        mq = pow(c, (q + 1) // 4, q)

        yp = pow(p, -1, q)
        yq = pow(q, -1, p)

        r1 = (mp * q * yq + mq * p * yp) % n
        r2 = n - r1
        r3 = (mp * q * yq - mq * p * yp) % n
        r4 = n - r3

        # Rabin decryption yields 4 candidate roots; redundancy (root must be
        # a valid character code) picks out the real plaintext character.
        for root in (r1, r2, r3, r4):
            if 0 <= root < alphabet_size:
                plaintext += chr(root)
                break

    return plaintext


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


# ---------- Centralized Key Management Service ----------

class RabinKeyManagementService:
    """Key management for HealthCare Inc.'s Rabin-based patient data system."""

    def __init__(self, key_bits=1024, renewal_interval_seconds=31536000):  # ~12 months
        self.key_bits = key_bits
        self.renewal_interval = renewal_interval_seconds
        self.facilities = {}          # name -> record
        self.audit_log = []
        self._master_key = get_random_bytes(16)   # protects private keys at rest

    def _log(self, action, facility):
        entry = (time.strftime("%Y-%m-%d %H:%M:%S"), action, facility)
        self.audit_log.append(entry)
        print(f"[AUDIT] {entry[0]} | {action:<18} | {facility}")

    def _seal(self, p, q):
        """Secure storage: private key is encrypted at rest with a master key,
        never kept in the clear -- satisfies the 'not accessible to
        unauthorized parties' requirement (and HIPAA's encryption-at-rest
        expectation for anything touching patient data)."""
        return aes_encrypt(self._master_key, f"{p},{q}")

    def _unseal(self, sealed):
        p, q = aes_decrypt(self._master_key, sealed).split(",")
        return int(p), int(q)

    def _require_active(self, facility):
        record = self.facilities.get(facility)
        if not record or not record["active"]:
            raise PermissionError(f"'{facility}' has no active keys")
        return record

    # ---- key generation ----
    def generate_for(self, facility):
        n, (p, q) = rabin_generate_keys(self.key_bits)
        self.facilities[facility] = {
            "n": n,
            "sealed_private": self._seal(p, q),
            "active": True,
            "created_at": time.time(),
        }
        self._log("KEY_GENERATED", facility)
        return n

    # ---- key distribution ("secure API") ----
    def get_public_key(self, facility):
        record = self._require_active(facility)
        self._log("PUBLIC_KEY_ISSUED", facility)
        return record["n"]

    def get_private_key(self, facility, requester):
        """Only the facility itself may request its own private key."""
        record = self._require_active(facility)

        if requester != facility:
            self._log("PRIVATE_KEY_DENIED", facility)
            raise PermissionError(f"'{requester}' is not authorized for {facility}'s private key")

        self._log("PRIVATE_KEY_ISSUED", facility)
        return self._unseal(record["sealed_private"])

    # ---- revocation ----
    def revoke(self, facility):
        self._require_active(facility)
        self.facilities[facility]["active"] = False
        self._log("KEY_REVOKED", facility)

    # ---- renewal ----
    def renew(self, facility):
        self._require_active(facility)
        self.generate_for(facility)
        self._log("KEY_RENEWED", facility)

    def renew_all_due(self):
        """Run periodically (e.g. by a scheduled job) to rotate any keys
        older than the renewal interval."""
        now = time.time()
        for facility, record in list(self.facilities.items()):
            if record["active"] and now - record["created_at"] >= self.renewal_interval:
                self.renew(facility)


if __name__ == "__main__":
    kms = RabinKeyManagementService(key_bits=1024, renewal_interval_seconds=5)

    for facility in ("Hospital-A", "Clinic-B"):
        kms.generate_for(facility)

    # Distribution + encryption/decryption of a patient record
    n = kms.get_public_key("Hospital-A")
    ciphertext = rabin_encrypt(n, "Patient record #4471")

    p, q = kms.get_private_key("Hospital-A", requester="Hospital-A")
    decrypted = rabin_decrypt(n, p, q, ciphertext)

    print("\nEncrypted patient record (truncated):", ciphertext[:60], "...")
    print("Decrypted patient record            :", decrypted)

    # Access control: another facility can't fetch Hospital-A's private key
    try:
        kms.get_private_key("Hospital-A", requester="Clinic-B")
    except PermissionError as e:
        print("\nAccess control worked:", e)

    # Revocation: a facility closes down
    print("\nRevoking Clinic-B (facility closed)...")
    kms.revoke("Clinic-B")
    try:
        kms.get_public_key("Clinic-B")
    except PermissionError as e:
        print("Revocation enforced:", e)

    # Renewal: simulate the 12-month rotation window elapsing
    print("\nWaiting for scheduled renewal window...")
    time.sleep(6)
    kms.renew_all_due()

    print("\n--- Audit Log (for compliance reporting) ---")
    for entry in kms.audit_log:
        print(entry)

    print("""
--- Rabin vs RSA trade-off analysis ---
Security guarantee : Breaking Rabin is *provably* as hard as factoring n (a
                      proven reduction). RSA's security is only *believed* to
                      be related to factoring -- there's no proof that
                      breaking RSA requires factoring n.
Encryption speed    : Rabin encryption is a single modular squaring (m^2 mod n)
                      -- faster than RSA's exponentiation by e (e.g. 65537,
                      ~17 modular squarings).
Decryption speed    : Comparable -- both need modular exponentiations of
                      similar size (Rabin via CRT on p, q; RSA via d or CRT).
Decryption ambiguity: Rabin decryption yields 4 candidate square roots, so
                      the scheme needs redundancy/padding to identify the
                      correct plaintext. RSA decryption is unique -- no
                      ambiguity, simpler to implement correctly.
Chosen-ciphertext risk: A naive Rabin decryption oracle can leak the
                      factorization of n (an attacker can derive p and q from
                      two different square roots), so proper padding (e.g.
                      Rabin-OAEP) is essential. RSA has the analogous risk and
                      needs OAEP too, but Rabin's exposure is more direct.
Key generation      : Both require two large primes; Rabin additionally
                      requires p, q = 3 (mod 4), a mild extra constraint that
                      RSA does not have.
Adoption            : RSA is far more widely deployed and standardized
                      (TLS, PGP, etc.); Rabin is mostly used in academic /
                      research settings today.
""")
