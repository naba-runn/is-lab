# Plain-text file helpers. Text only: no JSON, no bytes.
#
# Reading a file that doesn't exist yet returns "" / [] instead of crashing,
# so "view records" works on a fresh start.
#
# Everything you store is text. A big number (an RSA signature) comes back as
# a string, so convert it back with int(...).

import os


def file_exists(path):
    return os.path.exists(path)


# ---------- whole-file read / write ----------

def read_file(path):
    """The whole file as one string ("" if the file doesn't exist)."""
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path, text):
    """Replaces the file's contents ("w" erases whatever was there)."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def append_file(path, text):
    """Adds to the end of the file, keeping what's already there."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def clear_file(path):
    write_file(path, "")


# ---------- line by line ----------

def read_lines(path):
    """List of lines, newline removed, blank lines skipped ([] if no file)."""
    return [line for line in read_file(path).splitlines() if line.strip()]


def write_lines(path, lines):
    """Replaces the file with one item per line."""
    write_file(path, "".join(str(line) + "\n" for line in lines))


def append_line(path, line):
    append_file(path, str(line) + "\n")


# ---------- records: one record per line, fields joined with "|" ----------
# A field must not contain "|" or a newline.

def append_record(path, fields):
    append_line(path, "|".join(str(field) for field in fields))


def read_records(path):
    """List of records; each record is a list of strings."""
    return [line.split("|") for line in read_lines(path)]


def find_records(path, field_index, value):
    """Every record whose field number `field_index` equals `value`."""
    return [r for r in read_records(path) if r[field_index] == str(value)]


if __name__ == "__main__":
    path = "demo_notes.txt"
    clear_file(path)

    print("missing file reads as:", repr(read_file("no_such_file.txt")), read_lines("no_such_file.txt"))

    write_file(path, "first line\n")
    append_line(path, "second line")
    print("read_file :", repr(read_file(path)))
    print("read_lines:", read_lines(path))

    # records: name | age | signature (a big number stored as text)
    clear_file(path)
    append_record(path, ["alice", 34, 123456789 ** 30])
    append_record(path, ["bob", 41, 42])
    records = read_records(path)
    print("all records :", [r[:2] for r in records])
    print("latest      :", records[-1][:2])
    print("find bob    :", find_records(path, 0, "bob")[0][:2])
    print("signature back to int:", int(records[0][2]) == 123456789 ** 30)

    os.remove(path)
