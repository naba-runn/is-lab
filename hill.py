import string

A = string.ascii_lowercase

K = [
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


text = "We live in an insecure world"

cipher = hill_encrypt(text, K)

print("Cipher:", cipher)