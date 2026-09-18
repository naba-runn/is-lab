import time
import random
import string
import hashlib


def generate_dataset(count, length=12):
    return [
        ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        for _ in range(count)
    ]


def hash_dataset(dataset, algorithm):
    start = time.perf_counter()
    hashes = [hashlib.new(algorithm, s.encode()).hexdigest() for s in dataset]
    elapsed = time.perf_counter() - start

    return hashes, elapsed


def find_collisions(dataset, hashes, truncate=None):
    seen = {}
    collisions = []

    for original, full_hash in zip(dataset, hashes):
        key = full_hash[:truncate] if truncate else full_hash

        if key in seen:
            collisions.append((seen[key], original, key))
        else:
            seen[key] = original

    return collisions


if __name__ == "__main__":
    dataset = generate_dataset(count=random.randint(50, 100))
    print(f"Dataset size: {len(dataset)} random strings")
    print()

    print(f"{'Algorithm':>10} {'Time (ms)':>12} {'Full-hash collisions':>22}")
    for algorithm in ("md5", "sha1", "sha256"):
        hashes, elapsed = hash_dataset(dataset, algorithm)
        collisions = find_collisions(dataset, hashes)
        print(f"{algorithm:>10} {elapsed * 1000:>12.4f} {len(collisions):>22}")

    print()
    print("Full-length MD5/SHA-1/SHA-256 hashes essentially never collide on a")
    print("dataset this small -- the collision probability is astronomically low,")
    print("which is exactly what makes them collision-resistant. To actually see")
    print("the collision-detection logic trigger, the hashes are truncated to 8")
    print("bits (2 hex chars) below, where the birthday paradox makes a collision")
    print("likely with only ~50-100 samples (256 possible values):")
    print()

    for algorithm in ("md5", "sha1", "sha256"):
        hashes, _ = hash_dataset(dataset, algorithm)
        collisions = find_collisions(dataset, hashes, truncate=2)
        print(f"  {algorithm}: {len(collisions)} collision(s) among truncated (8-bit) hashes")
        for a, b, h in collisions[:3]:
            print(f"    '{a}' and '{b}' both truncate to {h}")

    print()
    print("Findings:")
    print("- MD5 is fastest but is cryptographically broken (practical collision")
    print("  attacks exist); SHA-1 is also broken for collision resistance.")
    print("- SHA-256 is slower (larger internal state, more rounds) but has no")
    print("  known practical collision attack, which is why it's the recommended")
    print("  choice for integrity-sensitive applications today.")
