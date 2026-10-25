import time
from Crypto.Util.number import getPrime, getRandomRange


def dh_generate_parameters(bits=256):
    p = getPrime(bits)
    g = 2

    return p, g


def dh_generate_keypair(p, g):
    private_key = getRandomRange(2, p - 1)
    public_key = pow(g, private_key, p)

    return public_key, private_key      # (public, private) like every generator


def compute_shared_secret(their_public_key, my_private_key, p):
    return pow(their_public_key, my_private_key, p)


if __name__ == "__main__":
    p, g = dh_generate_parameters()
    print("Public Parameters (p, g) =", (p, g))

    t0 = time.perf_counter()
    alice_public, alice_private = dh_generate_keypair(p, g)
    bob_public, bob_private = dh_generate_keypair(p, g)
    keygen_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    alice_shared = compute_shared_secret(bob_public, alice_private, p)
    bob_shared = compute_shared_secret(alice_public, bob_private, p)
    exchange_time = time.perf_counter() - t0

    print("Alice private/public key :", alice_private, "/", alice_public)
    print("Bob   private/public key :", bob_private, "/", bob_public)
    print("Alice shared secret      :", alice_shared)
    print("Bob   shared secret      :", bob_shared)
    print("Keys match                :", alice_shared == bob_shared)
    print(f"Key generation time      : {keygen_time:.6f}s")
    print(f"Key exchange time        : {exchange_time:.6f}s")
