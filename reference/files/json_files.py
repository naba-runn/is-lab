# JSON file helpers. Use these when a record has several NAMED fields
# (encrypted, hash, signature, timestamp, ...) that you want back as a dict.
# For plain text or simple "|"-separated records, use text_files.py instead.
#
# Two ways to store, pick one per file:
#   * one JSON object per line ("JSON Lines")  -> append_record / read_records
#         good for a growing list of records; each new record is ADDED
#   * the whole file is one JSON value         -> write_json / read_json
#         good for a single dict or list you rewrite completely
#
# json handles huge integers exactly, so an RSA signature (600+ digits)
# comes back identical, as an int. Missing file -> [] / default, no crash.

import json
import os


def make_record(encrypted_text, **extra_fields):
    """make_record(cipher, hash=h, signature=s, timestamp=t) -> a dict."""
    record = {"encrypted": encrypted_text}
    record.update(extra_fields)

    return record


# ---------- one record per line (JSON Lines) ----------

def append_record(path, record):
    """Adds one record to the end of the file ("a" keeps the earlier ones)."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def read_records(path):
    """List of ALL records (dicts), oldest first. [] if the file is missing."""
    if not os.path.exists(path):
        return []

    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:                                   # skip blank lines
                records.append(json.loads(line))

    return records


def find_records(path, field, value):
    """Every record whose `field` equals `value`."""
    return [r for r in read_records(path) if r.get(field) == value]


# ---------- the whole file is one JSON value ----------

def write_json(path, data):
    """Replaces the file with `data` (a dict or list)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def read_json(path, default=None):
    """The stored dict/list, or `default` if the file is missing."""
    if not os.path.exists(path):
        return default

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    path = "demo_records.jsonl"
    if os.path.exists(path):
        os.remove(path)

    print("missing file reads as:", read_records("no_such_file.jsonl"))

    big_signature = 123456789 ** 80                     # ~650 digits, like an RSA signature
    append_record(path, make_record("aa11", name="alice", hash="h1", signature=big_signature, timestamp="t1"))
    append_record(path, make_record("bb22", name="bob", hash="h2", signature=42, timestamp="t2"))

    records = read_records(path)                        # ALL records
    print("count       :", len(records))
    print("latest      :", records[-1]["name"], records[-1]["timestamp"])
    print("find alice  :", find_records(path, "name", "alice")[0]["hash"])
    print("signature back identical (int):", records[0]["signature"] == big_signature)
    os.remove(path)

    # whole-file JSON
    write_json("demo_keys.json", {"n": big_signature, "e": 65537})
    print("read_json   :", read_json("demo_keys.json")["e"], "| missing ->", read_json("nope.json", default={}))
    os.remove("demo_keys.json")
