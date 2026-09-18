from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, getRandomRange
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_lib, padding
from cryptography.hazmat.primitives import hashes


# ---- from ciphers/rsa.py (verbatim) ----

def rsa_generate_keys():
    private_key = rsa_lib.generate_private_key(public_exponent=65537, key_size=2048)
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


# ---- from ciphers/dh.py (verbatim) ----

def dh_generate_parameters(bits=256):
    p = getPrime(bits)
    g = 2

    return p, g


def dh_generate_keypair(p, g):
    private_key = getRandomRange(2, p - 1)
    public_key = pow(g, private_key, p)

    return private_key, public_key


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


# ---------- Key Management: generation, distribution, revocation ----------

class KeyManager:
    """Central key management for SecureCorp's subsystems.

    Every subsystem gets an RSA keypair (used to authenticate its Diffie-Hellman
    exchanges) and shares one set of DH parameters (p, g). New subsystems can be
    registered at any time, which is what makes this scale to future subsystems
    without changing any existing code.
    """

    def __init__(self, dh_bits=256):
        self.dh_p, self.dh_g = dh_generate_parameters(dh_bits)
        self.subsystems = {}   # name -> key material + active flag

    def register(self, name):
        rsa_private, rsa_public, _, _, _ = rsa_generate_keys()
        dh_private, dh_public = dh_generate_keypair(self.dh_p, self.dh_g)

        self.subsystems[name] = {
            "rsa_private": rsa_private,
            "rsa_public": rsa_public,
            "dh_private": dh_private,
            "dh_public": dh_public,
            "active": True,
        }
        print(f"[KeyManager] Registered subsystem '{name}'")

    def revoke(self, name):
        self._require_active(name)
        self.subsystems[name]["active"] = False
        print(f"[KeyManager] Revoked keys for subsystem '{name}'")

    def _require_active(self, name):
        info = self.subsystems.get(name)
        if not info or not info["active"]:
            raise PermissionError(f"'{name}' is not a registered/active subsystem")
        return info


# ---------- Secure Communication: RSA-protected Diffie-Hellman channel ----------

def derive_aes_key(shared_secret):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(shared_secret).encode())
    return digest.finalize()[:16]


def establish_session_key(manager, name_a, name_b):
    """A's DH public value is RSA-encrypted for B, so only B can use it to
    derive the shared secret -- this is the "RSA + Diffie-Hellman" combination."""
    a = manager._require_active(name_a)
    b = manager._require_active(name_b)

    encrypted_for_b = rsa_encrypt(b["rsa_public"], str(a["dh_public"]))
    dh_public_a = int(rsa_decrypt(b["rsa_private"], encrypted_for_b))

    shared_secret = pow(dh_public_a, b["dh_private"], manager.dh_p)
    return derive_aes_key(shared_secret)


def send_document(session_key, plaintext):
    return aes_encrypt(session_key, plaintext)


def receive_document(session_key, ciphertext):
    return aes_decrypt(session_key, ciphertext)


if __name__ == "__main__":
    manager = KeyManager()

    for name in ("FinanceSystem", "HRSystem", "SupplyChainSystem"):
        manager.register(name)

    # Finance -> HR: send a financial report
    key_ab = establish_session_key(manager, "FinanceSystem", "HRSystem")
    ciphertext = send_document(key_ab, "Q3 financial report: revenue up 8%")
    print("\nFinance -> HR ciphertext:", ciphertext)
    print("HR decrypts it as       :", receive_document(key_ab, ciphertext))

    # HR -> Supply Chain: send an employee-linked procurement order
    key_bc = establish_session_key(manager, "HRSystem", "SupplyChainSystem")
    ciphertext2 = send_document(key_bc, "Procurement order #221 for new hires")
    print("\nHR -> SupplyChain ciphertext:", ciphertext2)
    print("SupplyChain decrypts it as  :", receive_document(key_bc, ciphertext2))

    # Scalability: a brand-new subsystem joins later with zero changes elsewhere
    manager.register("LogisticsSystem")
    key_cd = establish_session_key(manager, "SupplyChainSystem", "LogisticsSystem")
    ciphertext3 = send_document(key_cd, "Shipment manifest #77")
    print("\nSupplyChain -> Logistics ciphertext:", ciphertext3)
    print("Logistics decrypts it as           :", receive_document(key_cd, ciphertext3))

    # Key revocation: a compromised/decommissioned subsystem loses access
    manager.revoke("SupplyChainSystem")
    try:
        establish_session_key(manager, "HRSystem", "SupplyChainSystem")
    except PermissionError as e:
        print("\nRevocation enforced as expected:", e)
