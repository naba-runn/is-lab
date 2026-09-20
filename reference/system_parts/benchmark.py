# Time any functions and print a comparison table.
#
# Few repeats for slow operations (key generation: 5-20), many for fast ones
# (one hash or one AES block: 1000+). Full example: problems/des_vs_aes256.py

import time
import hashlib


def measure(fn, *args, repeats=1000):
    """(last result, average seconds per call)"""
    start = time.perf_counter()
    for _ in range(repeats):
        result = fn(*args)

    return result, (time.perf_counter() - start) / repeats


def compare(jobs, repeats=1000):
    """jobs: {"name": (function, (args...))}. Prints microseconds per call."""
    print(f"{'Operation':<12} {'avg (us)':>12}")
    for name, (fn, args) in jobs.items():
        _, seconds = measure(fn, *args, repeats=repeats)
        print(f"{name:<12} {seconds * 1e6:>12.2f}")


if __name__ == "__main__":
    data = b"Performance Testing of Encryption Algorithms"

    compare({
        "MD5": (hashlib.md5, (data,)),
        "SHA-1": (hashlib.sha1, (data,)),
        "SHA-256": (hashlib.sha256, (data,)),
    })
