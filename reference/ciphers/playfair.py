def create_matrix(key):
    key = key.lower().replace('j', 'i')
    alphabet = "abcdefghijklmnopqrstuvwxyz"

    chars = ""

    for c in key + alphabet:
        if c == 'j':
            c = 'i'
        if c not in chars:
            chars += c

    return [chars[i:i+5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = ''.join(c for c in text.lower() if c.isalpha())
    text = text.replace('j', 'i')

    pairs = []
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 == len(text):
            pairs.append(a + 'x')
            i += 1

        elif text[i + 1] == a:
            pairs.append(a + 'x')
            i += 1

        else:
            pairs.append(a + text[i + 1])
            i += 2

    return pairs


def playfair_encrypt(text, key):
    matrix = create_matrix(key)

    position = {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }

    result = ""

    for a, b in prepare_text(text):

        r1, c1 = position[a]
        r2, c2 = position[b]

        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]

        # Same column
        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]

        # Rectangle
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def playfair_decrypt(cipher, key):
    matrix = create_matrix(key)

    position = {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }

    cipher = ''.join(c for c in cipher.lower() if c.isalpha())

    result = ""

    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i + 1]

        r1, c1 = position[a]
        r2, c2 = position[b]

        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        # Same column
        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        # Rectangle
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


if __name__ == "__main__":
    text = "The key is hidden under the door pad"
    key = "GUIDANCE"

    print("Matrix:")
    for row in create_matrix(key):
        print(row)

    cipher = playfair_encrypt(text, key)
    print("Cipher :", cipher)
    print("Plain  :", playfair_decrypt(cipher, key))
