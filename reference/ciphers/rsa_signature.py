# RSA digital signature -- SAME interface as every other *_signature.py:
#
#   rsa_sign(message, d, n)                -> signature as a STRING
#   rsa_verify(message, signature, e, n)   -> True / False
#
# The signature may be passed as that string or as an int (e.g. read back from a
# text file) -- verify converts it. The SHA-256 of the message is signed, so a
# message of any length works.
#
# rsa_recover() is only for the lab exercise where a signature was made
# directly on short text ("ALICE") and you must show the text it turns back into.

import hashlib


def rsa_message_number(message, n):
    """What is actually signed: SHA-256 of the message as a number, reduced mod n."""
    return int.from_bytes(hashlib.sha256(message.encode()).digest(), "big") % n


def rsa_sign(message, d, n):
    return str(pow(rsa_message_number(message, n), d, n))


def rsa_verify(message, signature, e, n):
    return pow(int(signature), e, n) == rsa_message_number(message, n)


def rsa_recover(signature, e, n):
    """Textbook check from the lab: signature^e mod n turned back into text."""
    m = pow(int(signature), e, n)
    length = (m.bit_length() + 7) // 8

    return m.to_bytes(length, "big").decode(errors="replace")


if __name__ == "__main__":
    # The exact RSA keys and signatures from the "Using Digital Signatures"
    # lab -- reproduced here in code instead of the online RSA tool.
    n = int(
        "d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a"
        "68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55f"
        "dcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474ba"
        "bc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549", 16
    )
    d = int(
        "47b9cfde843176b88741d68cf096952e950813151058ce46f2b048791a26e507a"
        "1095793c12bae1e09d82213ad9326928cf7c2350acb19c98f19d32d577d666cd7"
        "bb8b2b5ba629d25ccf72a5ceb8a8da038906c84dcdb1fe677dffb2c029fd892631"
        "8eede1b58272af22bda5c5232be066839398e42f5352df58848adad11a1", 16
    )
    e = 0x10001

    alice_signature_hex = """
        c8 93 a9 0d 8f 4e c5 c3 64 ec 86 9d 2b 2e c9 21 e3 8b
        ab 23 4a 4f 45 e8 96 9b 98 be 25 41 15 9e ab 6a fb 75
        9a 13 b6 26 04 c0 60 72 28 1a 73 45 71 83 42 d4 7f 57
        d1 ac 91 8c ae 2f 3b d2 99 30 3e e8 a8 3a b3 5d fb 4a
        c9 18 19 fd 3f 0c 0a 1f 3d a4 a4 fe 02 9d 96 2f 50 34
        d3 95 55 e0 b7 2a 46 a4 9e ae 80 c9 77 43 16 c0 ab fd
        dc 88 95 05 56 df c4 fc 13 a6 48 a3 3c e2 87 52 c5 3f
        0c 0d
    """
    alice_signature = int("".join(alice_signature_hex.split()), 16)

    # Step 2: Bob checks Alice's lab signature (made directly on the text)
    print("Alice's signature recovers to:", rsa_recover(alice_signature, e, n))

    # Step 3: Bob signs his own response (SHA-256 of the message is signed)
    bob_signature = rsa_sign("BOB", d, n)
    print("Bob's signature              :", bob_signature[:40] + "...")

    # Step 4: Alice verifies Bob's signature -- True / False like every verify
    print("Bob's signature valid        :", rsa_verify("BOB", bob_signature, e, n))
    print("valid for 'BOB!' (tampered)  :", rsa_verify("BOB!", bob_signature, e, n))
    print("valid when read from a file  :", rsa_verify("BOB", str(bob_signature), e, n))
