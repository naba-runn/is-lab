def custom_hash(data):
    """djb2-style hash: start at 5381, and for each character multiply the
    running hash by 33 and add the character's ASCII value. An XOR-shift step
    mixes the bits further, and the result is masked back to 32 bits after
    every character so it never grows unbounded."""
    hash_value = 5381

    for char in data:
        hash_value = (hash_value * 33) + ord(char)
        hash_value ^= (hash_value >> 13)      # bitwise mixing
        hash_value &= 0xFFFFFFFF              # keep to 32 bits

    return format(hash_value, "08x")      # hex string, like every hash in hashing.py


if __name__ == "__main__":
    messages = ["Hello, World!", "Hello, World?", "Hello, World!!", "Information Security"]

    for message in messages:
        print(f"custom_hash({message!r}) = {custom_hash(message)}")

    print()
    print("Note: 'Hello, World!' and 'Hello, World?' differ by one character")
    print("but produce fairly similar-looking hashes above -- this simple djb2-")
    print("style function mixes bits well enough for a hash table, but it's not")
    print("a cryptographic hash. See hash_comparison.py for MD5/SHA-1/SHA-256,")
    print("which are specifically designed so a 1-bit input change flips roughly")
    print("half the output bits.")
