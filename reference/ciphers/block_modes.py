# AES or DES in any mode: ECB, CBC, CFB, OFB, CTR.
#
# key / iv / nonce may be a str (used as text) or bytes. If a question gives
# you HEX, pass bytes.fromhex("...") instead of the string.
#
# Output is hex. For CBC/CFB/OFB the iv is put in front of the ciphertext, and
# for CTR the nonce is (same idea as ciphers/aes.py), so decrypt needs only the
# key. ECB has no iv.
#
# Sizes:  AES block = 16 bytes (key 16/24/32, iv 16, ctr nonce 8)
#         DES block =  8 bytes (key 8,         iv  8, ctr nonce 4)

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

ALGORITHMS = {"aes": AES, "des": DES}
PADDED_MODES = ("ecb", "cbc")            # CFB, OFB, CTR need no padding


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


if __name__ == "__main__":
    message = "Secure Communication"

    # DES in CBC with a given key and iv (a manual exercise)
    ciphertext = block_encrypt("des", "cbc", "A1B2C3D4", message, iv="12345678")
    print("DES CBC  :", ciphertext)
    print("decrypted:", block_decrypt("des", "cbc", "A1B2C3D4", ciphertext))

    # AES in CTR with a hex key and a hex nonce (a manual exercise)
    key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    nonce = bytes.fromhex("0000000000000000")
    ciphertext = block_encrypt("aes", "ctr", key, "Cryptography Lab Exercise", iv=nonce)
    print("AES CTR  :", ciphertext)
    print("decrypted:", block_decrypt("aes", "ctr", key, ciphertext))

    # every algorithm x mode combination round-trips
    for algorithm, key in (("aes", "1234567890123456"), ("des", "12345678")):
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr"):
            assert block_decrypt(algorithm, mode, key, block_encrypt(algorithm, mode, key, message)) == message
    print("all 10 algorithm/mode combinations round-trip")
