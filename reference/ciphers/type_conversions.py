# Every conversion between the data types that show up constantly in this
# codebase: text, bytes, hex strings, and big integers (keys, signatures).
# Not a cipher -- just the plumbing every cipher/system question needs.
#
# Rule of thumb for WHICH conversion you need:
#   Got plain text, need bytes for a Crypto.Cipher call      -> str_to_bytes
#   Got bytes back from a cipher, need to print/store it     -> bytes_to_hex
#   Got a hex string (a key, a ciphertext), need real bytes  -> hex_to_bytes
#   Got a big number (n, e, d, a signature), need it as text -> int_to_str
#   Got a number back from a text file, need it as a number  -> str_to_int
#   Need to inspect/flip individual bits                     -> bytes_to_bits / bits_to_bytes


# ---------- str <-> bytes ----------

def str_to_bytes(text):
    return text.encode()


def bytes_to_str(data):
    return data.decode()


# ---------- bytes <-> hex string ----------
# What every ciphers/*_encrypt function returns, and what *_decrypt expects.

def bytes_to_hex(data):
    return data.hex()


def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)


# ---------- hex string <-> int ----------

def hex_to_int(hex_string):
    return int(hex_string, 16)


def int_to_hex(number):
    return format(number, "x")   # no "0x" prefix, unlike hex(number)


# ---------- int <-> bytes ----------
# How a signature/key travels as raw bytes instead of decimal text.

def int_to_bytes(number):
    length = (number.bit_length() + 7) // 8
    return number.to_bytes(length, "big")


def bytes_to_int(data):
    return int.from_bytes(data, "big")


# ---------- str (decimal digits) <-> int ----------
# What EVERY number looks like after a round trip through a text file
# (read_lines / read_records) -- always convert back with int(...).

def int_to_str(number):
    return str(number)


def str_to_int(text):
    return int(text)


# ---------- single character <-> int ----------
# ord/chr -- what every classical cipher and ElGamal/Rabin's per-character
# encryption is built on.

def char_to_int(char):
    return ord(char)


def int_to_char(number):
    return chr(number)


# ---------- bytes <-> bits (binary string) ----------
# For showing/flipping individual bits rather than whole bytes.

def bytes_to_bits(data):
    return ''.join(format(byte, '08b') for byte in data)


def bits_to_bytes(bits):
    return int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')


# ---------- bytes <-> bytearray ----------
# bytes is immutable; flipping one byte/bit needs a mutable bytearray first.

def bytes_to_bytearray(data):
    return bytearray(data)


def bytearray_to_bytes(data):
    return bytes(data)


# ---------- list of fields <-> one "|"-joined string ----------
# What files/text_files.py's append_record / read_records do internally.

def fields_to_line(fields):
    return "|".join(str(field) for field in fields)


def line_to_fields(line):
    return line.split("|")


if __name__ == "__main__":
    text = "Hello"

    data = str_to_bytes(text)
    print("str_to_bytes  :", data)
    print("bytes_to_str  :", bytes_to_str(data))

    hex_string = bytes_to_hex(data)
    print("bytes_to_hex  :", hex_string)
    print("hex_to_bytes  :", hex_to_bytes(hex_string))

    number = hex_to_int(hex_string)
    print("hex_to_int    :", number)
    print("int_to_hex    :", int_to_hex(number))

    data_back = int_to_bytes(number)
    print("int_to_bytes  :", data_back)
    print("bytes_to_int  :", bytes_to_int(data_back))

    decimal_text = int_to_str(number)
    print("int_to_str    :", decimal_text)
    print("str_to_int    :", str_to_int(decimal_text))

    print("char_to_int('A'):", char_to_int("A"))
    print("int_to_char(65) :", int_to_char(65))

    bits = bytes_to_bits(data)
    print("bytes_to_bits :", bits)
    print("bits_to_bytes :", bits_to_bytes(bits))

    mutable = bytes_to_bytearray(data)
    mutable[0] ^= 0xFF                       # flip every bit of the first byte
    print("flipped byte  :", bytearray_to_bytes(mutable))

    fields = ["alice", 34, 123456789 ** 10]
    line = fields_to_line(fields)
    print("fields_to_line:", line)
    print("line_to_fields:", line_to_fields(line))

    # round-trip sanity check
    assert bytes_to_str(hex_to_bytes(bytes_to_hex(str_to_bytes(text)))) == text
    assert int_to_str(str_to_int("123456789012345678901234567890")) == "123456789012345678901234567890"
    assert bits_to_bytes(bytes_to_bits(data)) == data
    print("\nall round trips OK")
