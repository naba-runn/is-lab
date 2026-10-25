import hashlib


def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()


def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sha512_hash(text):
    return hashlib.sha512(text.encode()).hexdigest()


if __name__ == "__main__":
    message = "Information Security"

    print("Message :", message)
    print("MD5     :", md5_hash(message))
    print("SHA-1   :", sha1_hash(message))
    print("SHA-256 :", sha256_hash(message))
    print("SHA-512 :", sha512_hash(message))
