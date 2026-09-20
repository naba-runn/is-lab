# Key management: generate, distribute, revoke, renew, audit-log.
#
# KeyStore doesn't care which algorithm the keys are: give it any function
# that returns a (public_key, private_key) pair.
#
# Storing the private keys encrypted ("secure storage") is shown in
# problems/rabin_kms.py; the full enterprise version is problems/secure_corp.py.

import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa


# ---- from ciphers/glue_snippets.py (verbatim) ----

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class KeyStore:
    def __init__(self, keygen, max_age_seconds=31536000):      # default: 12 months
        self.keygen = keygen
        self.max_age_seconds = max_age_seconds
        self.keys = {}          # name -> {"public", "private", "active", "created_at"}
        self.audit_log = []     # (timestamp, action, name)

    def _log(self, action, name):
        self.audit_log.append((timestamp(), action, name))

    def _require_active(self, name):
        entry = self.keys.get(name)
        if not entry or not entry["active"]:
            raise PermissionError(f"'{name}' has no active keys")
        return entry

    def generate_for(self, name):
        public, private = self.keygen()
        self.keys[name] = {"public": public, "private": private,
                           "active": True, "created_at": time.time()}
        self._log("GENERATED", name)

    def get_public_key(self, name):
        entry = self._require_active(name)
        self._log("PUBLIC_KEY_ISSUED", name)
        return entry["public"]

    def get_private_key(self, name, requester):
        """Only the owner may fetch their own private key."""
        entry = self._require_active(name)
        if requester != name:
            self._log("PRIVATE_KEY_DENIED", name)
            raise PermissionError(f"'{requester}' may not read {name}'s private key")
        self._log("PRIVATE_KEY_ISSUED", name)
        return entry["private"]

    def revoke(self, name):
        self._require_active(name)
        self.keys[name]["active"] = False
        self._log("REVOKED", name)

    def renew_if_due(self, name):
        entry = self._require_active(name)
        if time.time() - entry["created_at"] >= self.max_age_seconds:
            self.generate_for(name)
            self._log("RENEWED", name)

    def renew_all_due(self):
        for name in list(self.keys):
            if self.keys[name]["active"]:
                self.renew_if_due(name)


def rsa_keypair():
    """Example keygen: any function returning (public, private) works."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    return private_key.public_key(), private_key


if __name__ == "__main__":
    store = KeyStore(rsa_keypair, max_age_seconds=1)

    store.generate_for("Hospital-A")
    store.generate_for("Clinic-B")

    store.get_public_key("Hospital-A")
    store.get_private_key("Hospital-A", requester="Hospital-A")
    try:
        store.get_private_key("Hospital-A", requester="Clinic-B")
    except PermissionError as error:
        print("blocked :", error)

    store.revoke("Clinic-B")
    try:
        store.get_public_key("Clinic-B")
    except PermissionError as error:
        print("revoked :", error)

    time.sleep(1.1)
    store.renew_all_due()                       # Hospital-A is older than 1 second

    print("\naudit log:")
    for entry in store.audit_log:
        print(" ", entry)
