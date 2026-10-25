import string

A = string.ascii_lowercase


def hill_demo_key():
    # FIXED demo key, not random -- use the key given in the question
    return [
        [3, 3],
        [2, 7]
    ]


def hill_encrypt(text, K):
    text = ''.join(c for c in text.lower() if c.isalpha())

    # Padding
    if len(text) % 2 != 0:
        text += 'x'

    cipher = ""

    for i in range(0, len(text), 2):

        x1 = A.index(text[i])
        x2 = A.index(text[i + 1])

        y1 = (K[0][0] * x1 + K[0][1] * x2) % 26
        y2 = (K[1][0] * x1 + K[1][1] * x2) % 26

        cipher += A[y1] + A[y2]

    return cipher


def hill_decrypt(cipher, K):
    cipher = ''.join(c for c in cipher.lower() if c.isalpha())

    det = (K[0][0] * K[1][1] - K[0][1] * K[1][0]) % 26
    det_inv = pow(det, -1, 26)

    inv_K = [
        [(K[1][1] * det_inv) % 26, (-K[0][1] * det_inv) % 26],
        [(-K[1][0] * det_inv) % 26, (K[0][0] * det_inv) % 26],
    ]

    plaintext = ""

    for i in range(0, len(cipher), 2):

        y1 = A.index(cipher[i])
        y2 = A.index(cipher[i + 1])

        x1 = (inv_K[0][0] * y1 + inv_K[0][1] * y2) % 26
        x2 = (inv_K[1][0] * y1 + inv_K[1][1] * y2) % 26

        plaintext += A[x1] + A[x2]

    return plaintext


if __name__ == "__main__":
    K = hill_demo_key()
    text = "We live in an insecure world"

    cipher = hill_encrypt(text, K)

    print("Cipher:", cipher)
    print("Plain :", hill_decrypt(cipher, K))
