import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, getRandomRange
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# ---------- Key Management: generation, distribution, revocation ----------

class KeyManager:
    """Central key management for SecureCorp's subsystems.

    Every subsystem gets an RSA keypair (used to authenticate its Diffie-Hellman
    exchanges) and shares one set of DH parameters (p, g). New subsystems can be
    registered at any time, which is what makes this scale to future subsystems
    without changing any existing code.
    """

    def __init__(self, dh_bits=256):
        self.dh_p = getPrime(dh_bits)
        self.dh_g = 2
        self.subsystems = {}   # name -> key material + active flag

    def register(self, name):
        rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dh_private = getRandomRange(2, self.dh_p - 1)
        dh_public = pow(self.dh_g, dh_private, self.dh_p)

        self.subsystems[name] = {
            "rsa_private": rsa_private,
            "rsa_public": rsa_private.public_key(),
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

    encrypted_for_b = b["rsa_public"].encrypt(
        str(a["dh_public"]).encode(),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    dh_public_a = int(b["rsa_private"].decrypt(
        encrypted_for_b,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode())

    shared_secret = pow(dh_public_a, b["dh_private"], manager.dh_p)
    return derive_aes_key(shared_secret)


def send_document(session_key, plaintext):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(pad(plaintext.encode(), AES.block_size))).hex()


def receive_document(session_key, ciphertext):
    raw = bytes.fromhex(ciphertext)
    iv, encrypted = raw[:AES.block_size], raw[AES.block_size:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode()


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
