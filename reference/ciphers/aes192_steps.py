from Crypto.Cipher import AES as _ReferenceAES
from Crypto.Util.Padding import pad, unpad

# Standard AES S-box (used for SubBytes and for SubWord in key expansion)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a, b):
    """Multiply two bytes in GF(2^8) (used by MixColumns)."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        a = _xtime(a)
        b >>= 1
    return product


# ---------- key expansion ----------

def aes192_key_expansion(key_bytes, verbose=True):
    Nk = len(key_bytes) // 4     # words in the key (6 for AES-192)
    Nr = Nk + 6                  # rounds (12 for AES-192)

    w = [list(key_bytes[4 * i:4 * i + 4]) for i in range(Nk)]

    rcon = 0x01
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]

        if i % Nk == 0:
            temp = temp[1:] + temp[:1]                # RotWord
            temp = [SBOX[b] for b in temp]             # SubWord
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif Nk > 6 and i % Nk == 4:
            temp = [SBOX[b] for b in temp]             # SubWord (AES-256 only)

        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    round_keys = [w[4 * r:4 * r + 4] for r in range(Nr + 1)]

    if verbose:
        print(f"Key expansion: {Nk}-word key -> {Nr} rounds -> {Nr + 1} round keys")
        for r, rk in enumerate(round_keys):
            flat = bytes(b for word in rk for b in word)
            print(f"  Round key {r:2d}: {flat.hex()}")

    return round_keys, Nr


# ---------- state helpers ----------

def _bytes_to_state(data):
    return [[data[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _print_state(label, state):
    print(f"    {label:<28}: {_state_to_bytes(state).hex()}")


def _add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[c][r] for c in range(4)] for r in range(4)]


def _sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    return [state[r][r:] + state[r][:r] for r in range(4)]


def _mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]

    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))

        new_state[0][c] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        new_state[1][c] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        new_state[2][c] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        new_state[3][c] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)

    return new_state


def _inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_shift_rows(state):
    return [state[r][-r:] + state[r][:-r] if r else state[r][:] for r in range(4)]


def _inv_mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]

    for c in range(4):
        a0, a1, a2, a3 = (state[r][c] for r in range(4))

        new_state[0][c] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        new_state[1][c] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        new_state[2][c] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        new_state[3][c] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)

    return new_state


# ---------- cipher ----------

def aes192_encrypt_block(block, key_bytes, verbose=True):
    """Encrypts exactly one 16-byte block, printing every step:
    key expansion -> initial round -> main rounds -> final round."""
    round_keys, Nr = aes192_key_expansion(key_bytes, verbose)

    state = _bytes_to_state(block)
    if verbose:
        print("\nInitial round:")
        _print_state("Input block", state)

    state = _add_round_key(state, round_keys[0])
    if verbose:
        _print_state("After AddRoundKey (round 0)", state)

    for rnd in range(1, Nr):
        if verbose:
            print(f"\nMain round {rnd}:")
        state = _sub_bytes(state)
        if verbose:
            _print_state("After SubBytes", state)
        state = _shift_rows(state)
        if verbose:
            _print_state("After ShiftRows", state)
        state = _mix_columns(state)
        if verbose:
            _print_state("After MixColumns", state)
        state = _add_round_key(state, round_keys[rnd])
        if verbose:
            _print_state(f"After AddRoundKey (round {rnd})", state)

    if verbose:
        print(f"\nFinal round ({Nr}) -- no MixColumns:")
    state = _sub_bytes(state)
    if verbose:
        _print_state("After SubBytes", state)
    state = _shift_rows(state)
    if verbose:
        _print_state("After ShiftRows", state)
    state = _add_round_key(state, round_keys[Nr])
    if verbose:
        _print_state(f"After AddRoundKey (round {Nr}, final)", state)

    return _state_to_bytes(state)


def aes192_decrypt_block(block, key_bytes, verbose=True):
    """Decrypts exactly one 16-byte block by running the cipher's steps in
    reverse: initial round -> main rounds -> final round, each using the
    inverse transform (InvShiftRows, InvSubBytes, InvMixColumns)."""
    round_keys, Nr = aes192_key_expansion(key_bytes, verbose)

    state = _bytes_to_state(block)
    if verbose:
        print("\nInitial round:")
        _print_state("Input block", state)

    state = _add_round_key(state, round_keys[Nr])
    if verbose:
        _print_state(f"After AddRoundKey (round {Nr})", state)

    for rnd in range(Nr - 1, 0, -1):
        if verbose:
            print(f"\nMain round {Nr - rnd}:")
        state = _inv_shift_rows(state)
        if verbose:
            _print_state("After InvShiftRows", state)
        state = _inv_sub_bytes(state)
        if verbose:
            _print_state("After InvSubBytes", state)
        state = _add_round_key(state, round_keys[rnd])
        if verbose:
            _print_state(f"After AddRoundKey (round {rnd})", state)
        state = _inv_mix_columns(state)
        if verbose:
            _print_state("After InvMixColumns", state)

    if verbose:
        print(f"\nFinal round ({Nr}) -- no InvMixColumns:")
    state = _inv_shift_rows(state)
    if verbose:
        _print_state("After InvShiftRows", state)
    state = _inv_sub_bytes(state)
    if verbose:
        _print_state("After InvSubBytes", state)
    state = _add_round_key(state, round_keys[0])
    if verbose:
        _print_state("After AddRoundKey (round 0, final)", state)

    return _state_to_bytes(state)


def aes192_demo_key():
    # FIXED demo key, not random -- use the key given in the question
    # 32 hex chars = 16 bytes as given in the assignment. AES-192 needs a
    # 24-byte (48 hex char) key, so the given block is extended with one more
    # repetition of itself to reach the required length.
    given = "FEDCBA9876543210FEDCBA9876543210"
    block = given[:32]
    return (block + block[:16]).upper()


def aes192_encrypt(key_hex, plaintext):
    key = bytes.fromhex(key_hex)
    block = pad(plaintext.encode(), 16)   # message fits in a single 16-byte block

    ciphertext = aes192_encrypt_block(block, key)

    reference = _ReferenceAES.new(key, _ReferenceAES.MODE_ECB).encrypt(block)
    print("\nMatches pycryptodome's reference AES-192 implementation:", ciphertext == reference)

    return ciphertext.hex()


def aes192_decrypt(key_hex, ciphertext):
    key = bytes.fromhex(key_hex)
    block = bytes.fromhex(ciphertext)

    padded = aes192_decrypt_block(block, key)

    reference = _ReferenceAES.new(key, _ReferenceAES.MODE_ECB).decrypt(block)
    print("\nMatches pycryptodome's reference AES-192 implementation:", padded == reference)

    return unpad(padded, 16).decode()


if __name__ == "__main__":
    key = aes192_demo_key()
    message = "Top Secret Data"

    print("Key (hex, 24 bytes) :", key)
    print("Message              :", message)
    print()

    ciphertext = aes192_encrypt(key, message)
    print("\nCiphertext :", ciphertext)

    print("\n" + "=" * 60)
    print("DECRYPTION")
    print("=" * 60)

    decrypted = aes192_decrypt(key, ciphertext)
    print("\nDecrypted  :", decrypted)
