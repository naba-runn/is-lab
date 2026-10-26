# Exam solution GENERATOR -- answers a few questions about the scenario and
# writes ONE standalone .py file you can run, show and edit.
#
#   python generate.py                         ask questions, write, self-test
#   python generate.py --preset evoting        build a sample question directly
#   python generate.py --list                  list the presets
#   python generate.py --preset hospital --out hosp.py --no-test
#
# No AI involved: every cipher function in the output is copied VERBATIM from
# ciphers/ (read with ast), and the rest comes from fixed templates. So the
# output has exactly the functions and conventions of the rest of this repo.
#
# The generated file:
#   - generates keys ONCE at start-up, never inside the menu loop
#   - stores one record per line in a .txt file next to the script
#   - verifies (hash + signature [+ time window]) BEFORE it decrypts
#   - has a "(demo) tamper" option to show that verification catches changes
#   - SHOW_STEPS (you answer it here): prints every value it computes -- keys, IV,
#     ciphertexts, data hashed, hash, signature, recomputed hash, Paillier /
#     RSA ciphertexts, running encrypted totals, trustee partials, tokens
#   - search: plain index (in clear) or SSE / PKSE; shows the COMPLETE record
#   - homomorphic SUM / AVERAGE / PRODUCT / vote count, each its own menu
#     action, over all records, chosen IDs, or a field filter via an index
#   - optional extras (all off unless you say yes):
#       login (username + password, salted PBKDF2) before each role menu
#       a password per record (key = PBKDF2(password, salt); only salt + check stored)
#       a different algorithm for chosen fields (e.g. Diagnosis with RSA)
#       every signer has their OWN key pair, plus a "Countersign" action
#       a decryption time window (decrypt only between two times)
#       socket mode:  python <file> server  /  python <file> client
#       field constraints (digits only, length, allowed values, email, phone,
#         date, custom regex, number range) -- invalid input is asked again
#       inputs from a .txt file: an 'Import records' action (one record per
#         line) and  python <file> --answers answers.txt  (no typing at all)
#   - runs every menu action by itself with:   python <file> test
#   - marks the numbers/names you should copy from the question with  TODO
#
# Two kinds of question are covered:
#   1. record systems   encrypt + hash + sign + store, then verify / decrypt /
#                       report / homomorphic tally / encrypted search per role
#                       (MediSecure, SecureVault, HealthSecure, Hospital,
#                       e-voting, grant portal, ...)
#   2. key exchange     Diffie-Hellman shared secret -> classical cipher on
#                       A-Z text with key validation (FieldTrack)
# A single algorithm on its own ("encrypt with Playfair", "Paillier add") is
# just the matching file in ciphers/ -- see guide/which_file.py.

import ast
import json
import os
import re
import subprocess
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
CIPHERS = os.path.join(HERE, "ciphers")


# =============================================================================
#  code assembly
# =============================================================================

def block(text):
    return textwrap.dedent(text).strip("\n")


def fill(text, **values):
    text = block(text)
    for name, value in values.items():
        text = text.replace("{{" + name + "}}", str(value))
    return text


def q(text):
    """A Python string literal in double quotes."""
    return json.dumps(text, ensure_ascii=False)


class Program:
    """Collects imports + code blocks and renders one standalone file."""

    def __init__(self):
        self.plain_imports = set()
        self.from_imports = {}
        self.blocks = []
        self.pulled = set()

    def need(self, line):
        if line.startswith("import "):
            for name in line[len("import "):].split(","):
                self.plain_imports.add(name.strip())
        else:
            module, names = re.match(r"from (\S+) import (.+)", line).groups()
            self.from_imports.setdefault(module, set()).update(n.strip() for n in names.split(","))

    def add(self, text, *imports):
        for line in imports:
            self.need(line)
        self.blocks.append(text)

    def use(self, filename, *names, patch=None):
        """Copy the named top-level functions / constants from ciphers/<filename>."""
        path = os.path.join(CIPHERS, filename)
        with open(path, encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)

        found = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in names:
                found[node.name] = ast.get_source_segment(source, node)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in names:
                        found[target.id] = ast.get_source_segment(source, node)
        missing = [n for n in names if n not in found]
        if missing:
            sys.exit("generate.py: %s not found in ciphers/%s" % (", ".join(missing), filename))

        new = [n for n in names if n not in self.pulled]
        if not new:
            return
        self.pulled.update(new)
        text = "\n\n\n".join(found[n] for n in new)
        if patch:
            text = text.replace(patch[0], patch[1])

        # only the imports the copied code actually uses
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if re.search(r"\b%s\b" % re.escape(alias.name.split(".")[0]), text):
                        self.plain_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if re.search(r"\b%s\b" % re.escape(alias.asname or alias.name), text):
                        self.from_imports.setdefault(node.module, set()).add(alias.name)

        self.blocks.append("# ---------- from ciphers/%s (verbatim) ----------\n\n%s" % (filename, text))

    def render(self, header):
        lines = [header, ""]
        lines += ["import " + name for name in sorted(self.plain_imports)]
        for module in sorted(self.from_imports, key=lambda m: (not m.startswith("datetime"), m)):
            lines.append("from %s import %s" % (module, ", ".join(sorted(self.from_imports[module]))))
        return "\n".join(lines) + "\n\n\n" + "\n\n\n".join(self.blocks) + "\n"


RESERVED = {"id", "hash", "time", "type", "input", "print", "file", "sum", "key", "rec",
            "plaintext", "rec_id", "records", "len", "str", "int", "list", "open", "format",
            "max", "min", "iv", "sig", "result", "status", "label", "short", "fields"}


def to_var(label):
    var = re.sub(r"\W+", "_", label.strip().lower()).strip("_") or "value"
    if var[0].isdigit():
        var = "f_" + var
    return var + "_value" if var in RESERVED else var


def parse_fields(spec):
    """'Name, Age:int, Report:file' -> [{'label','var','kind'}]"""
    fields = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        label, _, kind = part.partition(":")
        kind = kind.strip().lower() or "text"
        if kind not in ("text", "int", "file"):
            kind = "text"
        fields.append({"label": label.strip(), "var": to_var(label), "kind": kind})
    return fields


# =============================================================================
#  1. record systems
# =============================================================================

SYMMETRIC = {"aes128": ("AES-128-CBC", 16), "aes192": ("AES-192-CBC", 24), "aes256": ("AES-256-CBC", 32),
             "des": ("DES-CBC", 8), "3des": ("Triple DES", 24)}
ASYMMETRIC = {"rsa": "RSA (OAEP)", "elgamal": "ElGamal", "ecc": "ECC (ECIES)", "rabin": "Rabin"}
HASHES = {"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5"}
SIGNATURES = {"none": "no signature", "rsa": "RSA signature", "elgamal": "ElGamal signature",
              "schnorr": "Schnorr signature", "dsa": "DSA signature"}

BASE_ACTIONS = ["add", "view", "view_meta", "verify", "verify_one", "decrypt", "report", "search", "search_time"]
# Every homomorphic operation the four lab-7 schemes support. scheme: p = Paillier,
# m = textbook RSA, e = ElGamal (multiplicative), x = exponential ElGamal.
# shape: agg = combine the chosen records into ONE result; map = a result per
# record; pair = two records; votes = per-option counts.
#   NOT possible: Paillier ciphertext*ciphertext, RSA addition, ElGamal addition
#   (except the exponential variant), exponential-ElGamal multiplication.
OPS = {
    "sum":               ("p", "agg",   "Homomorphic SUM of %s (Paillier)"),
    "average":           ("p", "agg",   "Homomorphic AVERAGE of %s (Paillier sum / count)"),
    "scaled_sum":        ("p", "agg",   "Homomorphic SUM of %s x constant k (Paillier Enc(sum)^k)"),
    "add_const":         ("p", "map",   "Add constant k to each %s (Paillier Enc(m) * g^k)"),
    "scale_each":        ("p", "map",   "Multiply each %s by constant k (Paillier Enc(m)^k)"),
    "difference":        ("p", "pair",  "DIFFERENCE of %s between two records (Paillier Enc(a) / Enc(b))"),
    "compare":           ("p", "map",   "Is %s above a threshold? (Paillier subtract + blind, value hidden)"),
    "votes":             ("p", "votes", "Tally votes for %s (Paillier one-hot)"),
    "product":           ("m", "agg",   "Homomorphic PRODUCT of %s (textbook RSA)"),
    "scaled_product":    ("m", "agg",   "Homomorphic PRODUCT of %s x constant k (RSA Enc(P) * k^e)"),
    "rsa_scale_each":    ("m", "map",   "Multiply each %s by constant k (RSA Enc(m) * k^e)"),
    "rsa_power":         ("m", "map",   "Raise each %s to the power k (RSA Enc(m)^k)"),
    "eg_product":        ("e", "agg",   "Homomorphic PRODUCT of %s (ElGamal)"),
    "eg_scaled_product": ("e", "agg",   "Homomorphic PRODUCT of %s x constant k (ElGamal (c1, c2*k))"),
    "eg_scale_each":     ("e", "map",   "Multiply each %s by constant k (ElGamal (c1, c2*k))"),
    "eg_power":          ("e", "map",   "Raise each %s to the power k (ElGamal (c1^k, c2^k))"),
    "eg_sum":            ("x", "agg",   "Homomorphic SUM of %s (exponential ElGamal g^m)"),
}
HE_TYPES = {name: re.sub(r"\s+", " ", (label % "a field").replace("of a field", "").replace("each a field", "each value")
                        .replace("Is a field", "Is a value").replace("for a field", ""))
            for name, (_, _, label) in OPS.items()}


def action_labels(cfg):
    noun = cfg["noun"]
    labels = {
        "add": "Add new " + noun,
        "view": "View all stored " + noun + "s (encrypted)",
        "view_meta": "View IDs, timestamps, hashes and VALID/INVALID",
        "verify": "Verify all " + noun + "s (hash + signature)",
        "verify_one": "Verify one " + noun + " (no decryption shown)",
        "decrypt": "Verify, then decrypt one " + noun,
        "report": "Generate compliance report (no decryption)",
        "search": "Search " + noun + "s (" + " / ".join(m if m != "plain" else "plain index" for m in cfg["methods"]) + ")",
        "search_time": "Search by time range",
        "cosign": "Countersign a " + noun + " (with YOUR own key)",
        "show_keys": "Show every user's public key",
        "import": "Import " + noun + "s from a .txt file (no typing)",
    }
    for op in cfg["he"]:
        labels[op["action"]] = OPS[op["type"]][2] % op["label"] + {
            "ask": "", "pair": "", "all": " -- all records", "ids": " -- chosen IDs",
            "filter": " -- filter by " + op.get("filter_field", "")}[op["select"]]
    labels.update(cfg.get("labels", {}))
    return labels


DEFAULTS = {
    "name": "Secure Records System",
    "out": "exam_solution.py",
    "noun": "record",
    "id_label": "Record ID",
    "fields": "Name, Details",
    "enc": "aes256",
    "key_src": "random",          # random | typed_once | typed_each | password   ("wrap" = old name for wrap: record)
    "wrap": "none",               # RSA-encrypt the AES/DES key: none | record (fresh key per record) | file
    "iv_src": "random",           # random | typed
    "rsa_bits": 2048,
    "elgamal_given": None,        # [p, g, x] for ElGamal ENCRYPTION of the data
    "hash": "sha256",
    "hash_over": "ciphertext",    # ciphertext | plaintext
    "sig": "rsa",
    "extra": None,                # {"label": "Authorization code", "given": [p, g, x] or None}
    "he": [],                     # [{"type": "sum"|"average"|"product"|"votes", "field": label, "choices": [...]}]
    "trustees": 0,                # >1 -> threshold Paillier decryption
    "search": None,               # {"types": ["sse", "pkse"], "fields": [labels], "time": bool}
    "window": None,               # label, e.g. "voting period" -> timestamp must be inside it
    "roles": [],                  # [[role name, [actions]], ...]   [] -> one menu with everything
    "show_steps": True,           # print every value computed (keys, ciphertexts, hashes, signatures, totals)
    "persist": True,              # save keys to <name>_keys.txt on the first run, reuse them on later runs
    "decrypted_file": True,       # append every successful decryption to <name>_decrypted.txt
    "access_log": True,           # write <name>_access_log.txt
    "login": False,               # username + password (salted PBKDF2) before a role menu can be used
    "field_enc": {},              # {field label: algorithm} -> that field gets its OWN ciphertext
    "user_keys": False,           # every signer has their OWN key pair; the record stores who signed
    "cosign": False,              # adds a "Countersign" action: a second signature by another user
    "sockets": False,             # the same file also runs as  python file.py server / client
    "decrypt_window": None,       # label, e.g. "exam window" -> decryption only allowed inside it
    "constraints": {},            # {field label or ID label: rule}, see FIELD_PATTERNS / check_rule below
    "sign_time": True,            # sign hash|timestamp (True) or only the hash (False)
    "file_input": False,          # inputs from a .txt file: "Import records" action + --answers run mode
    "import_separator": ",",      # separator between the values on one line of the import file
}

# Field constraints (all optional; a rule is a dict):
#   text   : "pattern" (letters | digits | alnum | email | phone | date | a custom regex),
#            "min_len", "max_len", "allowed": [values], "examples": [valid values] (for custom regex)
#   number : "min", "max"
FIELD_PATTERNS = {"letters": ("[A-Za-z ]+", "letters only"),
                  "digits": ("[0-9]+", "digits only"),
                  "alnum": ("[A-Za-z0-9]+", "letters and digits only"),
                  "email": (r"[^@\s]+@[^@\s]+\.[^@\s]+", "an email address like name@mail.com"),
                  "phone": ("[0-9]{10}", "a 10-digit phone number"),
                  "date": (r"[0-9]{4}-[0-9]{2}-[0-9]{2}", "a date YYYY-MM-DD")}


def field_by_label(cfg, label):
    for f in cfg["fields"]:
        if f["label"].lower() == label.lower():
            return f
    sys.exit("generate.py: no data field called %r (fields: %s)" % (label, ", ".join(f["label"] for f in cfg["fields"])))


def as_text(f):
    return f["var"] if f["kind"] in ("text", "choice", "file") else "str(%s)" % f["var"]


def normalize(cfg):
    cfg = dict(DEFAULTS, **cfg)
    cfg["fields"] = parse_fields(cfg["fields"]) if isinstance(cfg["fields"], str) else cfg["fields"]
    if cfg["key_src"] == "wrap":
        cfg["wrap"] = "record"
    if cfg["key_src"] == "password":
        cfg["wrap"] = "none"                      # the key comes from each record's password
        if cfg["hash_over"] == "plaintext":
            print("note: hash of the plaintext would need every password to verify -> hash of the ciphertext")
            cfg["hash_over"] = "ciphertext"
    if cfg["enc"] not in SYMMETRIC:
        cfg["wrap"] = "none"
    if cfg["wrap"] == "record":
        cfg["key_src"] = "wrap"                   # internal name: a fresh key per record
    elif cfg["wrap"] == "file" and cfg["key_src"] == "typed_each":
        cfg["key_src"] = "typed_once"
    if cfg["enc"] not in SYMMETRIC:
        cfg["key_src"], cfg["iv_src"] = "-", "-"
    if cfg["enc"] == "3des":
        cfg["iv_src"] = "random"
    if cfg["hash_over"] == "plaintext" and cfg["key_src"] == "typed_each":
        print("note: hash of the plaintext needs the key to verify -> key typed once at start instead")
        cfg["key_src"] = "typed_once"

    # field constraints, keyed by the exact label (the ID counts as a field)
    rules = {}
    for label, rule in (cfg["constraints"] or {}).items():
        if label.lower() == cfg["id_label"].lower():
            rules[cfg["id_label"]] = dict(rule)
        else:
            f = field_by_label(cfg, label)
            if f["kind"] in ("text", "int"):
                rules[f["label"]] = dict(rule)
    cfg["rules"] = rules

    # fields with their own algorithm
    cfg["fenc"] = []
    for label, alg in (cfg["field_enc"] or {}).items():
        f = field_by_label(cfg, label)
        if alg not in SYMMETRIC and alg not in ASYMMETRIC:
            sys.exit("generate.py: unknown algorithm %r for field %s" % (alg, label))
        cfg["fenc"].append({"label": f["label"], "var": f["var"], "alg": alg})
    if cfg["cosign"]:
        cfg["user_keys"] = True
    if cfg["user_keys"] and cfg["sig"] == "none":
        cfg["sig"] = "rsa"
    if cfg["sockets"]:
        cfg["persist"] = True                     # client and server must share the keys file

    # homomorphic operations: one menu action each
    ops = cfg["he"] or []
    if isinstance(ops, dict):
        ops = [ops]
    for op in ops:
        f = field_by_label(cfg, op["field"])
        f["kind"] = "choice" if op["type"] == "votes" else "int"
        op["var"], op["label"] = f["var"], f["label"]
        op["action"] = op["type"] + "_" + f["var"]
        op["scheme"], op["shape"] = OPS[op["type"]][:2]
        op["store"] = "votes" if op["type"] == "votes" else op["scheme"] + "_" + f["var"]
        # which records it works on: ask (menu at run time) | all | ids | filter
        op["select"] = "pair" if op["type"] == "difference" else op.get("select", "ask")
        if op["select"] == "filter":
            op["filter_field"] = field_by_label(cfg, op["filter_field"])["label"]
            op["filter_method"] = {"sse": "SSE", "pkse": "PKSE"}.get(op.get("filter_method", "plain").lower(), "plain")
    if sum(op["type"] == "votes" for op in ops) > 1:
        sys.exit("generate.py: only one 'votes' operation is supported")
    cfg["he"] = ops
    for f in cfg["fields"]:
        rule = cfg["rules"].get(f["label"])
        if rule is None:
            continue
        if f["kind"] == "int":
            cfg["rules"][f["label"]] = {k: v for k, v in rule.items() if k in ("min", "max")}
        elif f["kind"] == "text":
            cfg["rules"][f["label"]] = {k: v for k, v in rule.items() if k not in ("min", "max")}
        else:
            del cfg["rules"][f["label"]]
        if not cfg["rules"].get(f["label"], True):
            del cfg["rules"][f["label"]]
    if not any(op["scheme"] == "p" for op in ops):
        cfg["trustees"] = 0

    # indexes: used by search AND by the "filter" option of homomorphic actions
    search = cfg["search"]
    if search:
        if "type" in search:
            search["types"] = [search.pop("type")]
        search["types"] = [t for t in search["types"] if t in ("sse", "pkse")]
        search.setdefault("time", False)
        index = search["fields"]
    elif ops:
        index = [f["label"] for f in cfg["fields"] if f["kind"] in ("text", "choice")]
    else:
        index = []
    index_types = list(search["types"]) if search else []
    for op in ops:
        if op["select"] == "filter":
            if op["filter_field"] not in index:
                index = list(index) + [op["filter_field"]]
            if op["filter_method"] != "plain" and op["filter_method"].lower() not in index_types:
                index_types.append(op["filter_method"].lower())
    cfg["index_types"] = index_types
    cfg["index_fields"] = [field_by_label(cfg, label)["label"] for label in index]
    cfg["methods"] = (["plain"] if index else []) + [t.upper() for t in index_types]
    cfg["time_methods"] = ["plain"] + (["SSE"] if "sse" in index_types else [])

    # which actions exist, which roles get them
    all_actions = BASE_ACTIONS + (["cosign"] if cfg["cosign"] else []) + (["show_keys"] if cfg["user_keys"] else []) \
        + (["import"] if cfg["file_input"] else []) + [op["action"] for op in ops]
    if not search:
        all_actions = [a for a in all_actions if a not in ("search", "search_time")]
    elif not search["time"]:
        all_actions.remove("search_time")

    def expand(actions):
        out = []
        for a in actions:
            for b in ([op["action"] for op in ops] if a == "tally" else [a]):
                if b in all_actions and b not in out:
                    out.append(b)
        return out

    if cfg["roles"]:
        cfg["roles"] = [[name, expand(actions)] for name, actions in cfg["roles"]]
        if cfg["file_input"] and not any("import" in actions for _, actions in cfg["roles"]):
            for _, actions in cfg["roles"]:          # whoever adds records may also import them
                if "add" in actions:
                    actions.insert(actions.index("add") + 1, "import")
    else:
        cfg["roles"] = [[None, list(all_actions)]]
    cfg["used"] = set(a for _, actions in cfg["roles"] for a in actions) | {"add"}
    return cfg


# ---------- homomorphic menu actions (one generated function per operation) ----------

SCHEME_CODE = {
    "p": dict(enc='paillier_encrypt(K["p_n"], K["p_g"], %s)', parse="int", mul='paillier_add(K["p_n"], total, c)',
              how="multiply mod n^2 = add plaintexts", dec="decrypt_total(%s)", start=0),
    "m": dict(enc='rsa_he_encrypt(K["he_n"], K["he_e"], %s)', parse="int", mul='rsa_he_multiply(K["he_n"], total, c)',
              how="multiply mod n = multiply plaintexts", dec='rsa_he_decrypt(K["he_n"], K["he_d"], %s)', start=1),
    "e": dict(enc='elgamal_he_encrypt(K["eg_p"], K["eg_g"], K["eg_h"], %s)', parse="eg_parse",
              mul='elgamal_he_multiply(K["eg_p"], total, c)', how="(c1*c1', c2*c2') mod p = multiply plaintexts",
              dec='elgamal_he_decrypt(K["eg_p"], K["eg_x"], %s)', start=1),
    "x": dict(enc='elgamal_exp_encrypt(K["eg_p"], K["eg_g"], K["eg_h"], %s)', parse="eg_parse",
              mul='elgamal_he_multiply(K["eg_p"], total, c)', how="g^a * g^b = g^(a+b): adds the exponents",
              dec='elgamal_exp_decrypt(K["eg_p"], K["eg_g"], K["eg_x"], %s)', start=0),
}
AGG_TITLE = {"sum": "SUM", "average": "AVERAGE", "scaled_sum": "SUM x k", "product": "PRODUCT",
             "scaled_product": "PRODUCT x k", "eg_product": "PRODUCT", "eg_scaled_product": "PRODUCT x k", "eg_sum": "SUM"}
AGG_POST = {"scaled_sum": ('paillier_multiply_plain(K["p_n"], total, k)', "Enc(sum)^k mod n^2 = Enc(k * sum)"),
            "scaled_product": ('rsa_he_multiply_plain(K["he_n"], K["he_e"], total, k)', "Enc(P) * k^e mod n = Enc(k * P)"),
            "eg_scaled_product": ('elgamal_he_multiply_plain(K["eg_p"], total, k)', "(c1, c2 * k) mod p = Enc(k * P)")}
MAP_SPEC = {"add_const": ('paillier_add_plain(K["p_n"], K["p_g"], c, k)', "Enc(m) * g^k mod n^2 = Enc(m + k)", "%s + k"),
            "scale_each": ('paillier_multiply_plain(K["p_n"], c, k)', "Enc(m)^k mod n^2 = Enc(k * m)", "k * %s"),
            "rsa_scale_each": ('rsa_he_multiply_plain(K["he_n"], K["he_e"], c, k)', "Enc(m) * k^e mod n = Enc(k * m)", "k * %s"),
            "rsa_power": ('rsa_he_power(K["he_n"], c, k)', "Enc(m)^k mod n = Enc(m^k)", "%s ^ k"),
            "eg_scale_each": ('elgamal_he_multiply_plain(K["eg_p"], c, k)', "(c1, c2 * k) mod p = Enc(k * m)", "k * %s"),
            "eg_power": ('elgamal_he_power(K["eg_p"], c, k)', "(c1^k, c2^k) mod p = Enc(m^k)", "%s ^ k")}
NEEDS_K = set(AGG_POST) | set(MAP_SPEC)


def select_expr(op, purpose):
    """The generated line that picks the records -- fixed by what you answered in generate.py."""
    if op["select"] == "all":
        return "select_all()"
    if op["select"] == "ids":
        return "select_by_ids()"
    if op["select"] == "filter":
        return "select_by_filter(%s, %s)" % (q(op["filter_method"]), q(op["filter_field"]))
    return "choose_records(%s)" % q(purpose)


def he_function(op):
    kind, fn, label, store = op["type"], op["action"], op["label"], op["store"]
    title = OPS[kind][2] % label
    s = SCHEME_CODE[op["scheme"]]

    if kind == "votes":
        return fill(r'''
            def {{fn}}():
                """{{title}}: multiply the Enc(0/1) of every VALID ballot per option; decrypt only the totals."""
                records = {{select}}
                totals = [paillier_encrypt(K["p_n"], K["p_g"], 0) for _ in CHOICES]
                counted = []
                for rec in records:
                    if not is_valid(rec):
                        print(rec["id"], ": failed verification, NOT counted")
                        continue
                    for i, c in enumerate(rec["votes"].split(";")):
                        step("Enc(0/1) for " + CHOICES[i] + " in " + rec["id"], c)
                        totals[i] = paillier_add(K["p_n"], totals[i], int(c))
                    counted.append(rec["id"])
                print("Valid ballots counted:", counted)
                results = {}
                for choice, total in zip(CHOICES, totals):
                    show_value(choice + " encrypted total", short(str(total), 60))
                    results[choice] = decrypt_total(total)
                result_line("RESULT: " + str(results))
                log_access("{{fn}}", ",".join(counted), str(results))
                return results
        ''', fn=fn, title=title, select=select_expr(op, "vote count"))

    if kind == "difference":
        return fill(r'''
            def {{fn}}():
                """{{title}}: Enc(a) * Enc(b)^-1 mod n^2 = Enc(a - b)."""
                first = find_record(ask_text("First ID (a): "))
                second = find_record(ask_text("Second ID (b): "))
                if first is None or second is None:
                    print("Not found.")
                    return None
                for rec in (first, second):
                    if not is_valid(rec):
                        print(rec["id"], ": failed verification -- not used.")
                        return None
                ca, cb = int(first["{{store}}"]), int(second["{{store}}"])
                step("Enc({{label}}) of " + first["id"] + " (a)", ca)
                step("Enc({{label}}) of " + second["id"] + " (b)", cb)
                difference = paillier_subtract(K["p_n"], ca, cb)
                step("Enc(a) * Enc(b)^-1 mod n^2 = Enc(a - b)", difference)
                result = decrypt_total(difference)
                if result > K["p_n"] // 2:            # negative numbers decrypt as n - |value|
                    result -= K["p_n"]
                result_line("{{label}} of " + first["id"] + " - " + second["id"] + " = " + str(result))
                log_access("{{fn}}", first["id"] + "," + second["id"], str(result))
                return result
        ''', fn=fn, title=title, label=label, store=store)

    if kind == "compare":
        return fill(r'''
            def {{fn}}():
                """{{title}}: Enc(m - T) blinded by a random r > 0; only the SIGN is learned, never m."""
                records = {{select}}
                threshold = ask_int("Threshold T: ")
                results = {}
                for rec in records:
                    if not is_valid(rec):
                        print(rec["id"], ": failed verification, NOT included")
                        continue
                    c = int(rec["{{store}}"])
                    step("Enc({{label}}) of " + rec["id"], c)
                    difference = paillier_add_plain(K["p_n"], K["p_g"], c, -threshold)
                    step("Enc(m) * g^-T = Enc(m - T)", difference)
                    blinded = paillier_multiply_plain(K["p_n"], difference, getRandomRange(1, 2 ** 32))
                    step("Enc((m - T) * r), r random", blinded)
                    value = decrypt_total(blinded)
                    if value > K["p_n"] // 2:
                        value -= K["p_n"]
                    step("decrypted blinded value (only its sign means anything)", value)
                    results[rec["id"]] = value > 0
                    print("  " + rec["id"] + " : {{label}} " + ("ABOVE " if value > 0 else "NOT above ") + str(threshold))
                log_access("{{fn}}", ",".join(results), str(results))
                return results
        ''', fn=fn, title=title, label=label, store=store, select=select_expr(op, "threshold check of " + label))

    if op["shape"] == "map":
        transform, how, expr = MAP_SPEC[kind]
        return fill(r'''
            def {{fn}}():
                """{{title}}. Each new value is decrypted on its own."""
                records = {{select}}
                k = ask_int("Constant k: ")
                results = {}
                for rec in records:
                    if not is_valid(rec):
                        print(rec["id"], ": failed verification, NOT included")
                        continue
                    c = {{parse}}(rec["{{store}}"])
                    step("Enc({{label}}) of " + rec["id"], c)
                    new = {{transform}}
                    step("{{how}}", new)
                    results[rec["id"]] = {{dec}}
                    print("  " + rec["id"] + " : {{expr}} = " + str(results[rec["id"]]) + "    (k = " + str(k) + ")")
                log_access("{{fn}}", ",".join(results), str(results))
                return results
        ''', fn=fn, title=title, select=select_expr(op, title.split(" (")[0].lower()), parse=s["parse"], store=store, label=label,
                    transform=transform, how=how, dec=s["dec"] % "new", expr=expr % label)

    # agg: combine every chosen record into one encrypted result
    word = "total" if s["start"] == 0 else "product"
    lines = [
        "def %s():" % fn,
        '    """%s. Only the final result is decrypted."""' % title,
        "    records = " + select_expr(op, AGG_TITLE[kind].lower() + " of " + label)]
    if kind in NEEDS_K:
        lines.append('    k = ask_int("Constant k: ")')
    lines += [
        "    total = " + s["enc"] % s["start"],
        '    step("start with Enc(%d)", total)' % s["start"],
        "    counted = []",
        "    for rec in records:",
        "        if not is_valid(rec):",
        '            print(rec["id"], ": failed verification, NOT included")',
        "            continue",
        '        c = %s(rec["%s"])' % (s["parse"], store),
        '        step("Enc(%s) of " + rec["id"], c)' % label,
        "        total = " + s["mul"],
        '        step("encrypted %s after " + rec["id"] + " (%s)", total)' % (word, s["how"]),
        '        counted.append(rec["id"])',
        "    if not counted:",
        '        print("No valid records selected.")',
        "        return None"]
    if kind in AGG_POST:
        lines += ["    total = " + AGG_POST[kind][0], '    step("%s", total)' % AGG_POST[kind][1]]
    lines += ['    section("result")', '    show_value("encrypted result", short(str(total), 60))',
              "    result = " + s["dec"] % "total"]
    if op["scheme"] != "p":
        lines.append('    step("decrypted with the private key", result)')
    if kind == "average":
        lines += ["    average = result / len(counted)",
                  '    print("SUM =", result, " count =", len(counted))',
                  "    result = average"]
    lines += ['    result_line("%s of %s over " + ", ".join(counted) + " = " + str(result))' % (AGG_TITLE[kind], label),
              '    log_access("%s", ",".join(counted), str(result))' % fn,
              "    return result"]
    return "\n".join(lines)


def import_columns(cfg):
    """The values on one line of the import file, in the order add_record asks for them."""
    cols = [cfg["id_label"]] + [f["label"] + (" (file path)" if f["kind"] == "file" else "") for f in cfg["fields"]]
    if cfg["extra"]:
        cols.append(cfg["extra"]["label"])
    if cfg["key_src"] == "typed_each":
        cols.append("Key")
    if cfg["key_src"] == "password":
        cols.append("Password")
    if cfg["iv_src"] == "typed":
        cols.append("IV")
    if cfg["user_keys"] and not cfg["login"]:
        cols.append("Signer")
    return cols


def build_records(cfg):
    cfg = normalize(cfg)
    prog = Program()
    enc, sym = cfg["enc"], cfg["enc"] in SYMMETRIC
    wrap = cfg["key_src"] == "wrap"
    wrap_file = cfg["wrap"] == "file"
    persist = cfg["persist"]
    fenc = cfg["fenc"]
    falgs = set(f["alg"] for f in fenc)
    password = cfg["key_src"] == "password"
    login = cfg["login"]
    user_keys = cfg["user_keys"]
    cosign = cfg["cosign"]
    sockets = cfg["sockets"]
    dwin = cfg["decrypt_window"]
    need_rsa = enc == "rsa" or wrap or wrap_file or cfg["sig"] == "rsa" or "rsa" in falgs
    ops = cfg["he"]
    search = cfg["search"]
    types = cfg["index_types"]
    index_fields = cfg["index_fields"]
    schemes = set(op["scheme"] for op in ops)
    need_paillier = "p" in schemes or "pkse" in types
    need_rsa_he = "m" in schemes
    need_eg_he = "e" in schemes or "x" in schemes
    prefix = to_var(os.path.splitext(os.path.basename(cfg["out"]))[0])
    fields = cfg["fields"]
    sig = cfg["sig"]
    sig_msg = "hash|time" if cfg["sign_time"] else "hash"

    # ---------------- header ----------------
    stored = ["id", "enc"]
    if wrap:
        stored.append("key")
    if password:
        stored += ["salt", "pwcheck"]
    stored += ["f_" + f["var"] for f in fenc]
    if cfg["extra"]:
        stored.append("extra")
    for op in ops:
        if op["store"] not in stored:
            stored.append(op["store"])
    stored += ["time"] + (["signer"] if user_keys else []) + ["hash"]
    if sig != "none":
        stored.append("sig")
    if cosign:
        stored.append("cosigs")
    main_fields = [f for f in fields if f["var"] not in [x["var"] for x in fenc]]

    enc_name = SYMMETRIC[enc][0] if sym else ASYMMETRIC[enc]
    sym_name = enc_name.split("-CBC")[0]
    desc = {"id": cfg["id_label"] + " (plain, used to look records up)",
            "enc": enc_name + " of: " + (", ".join(f["label"] for f in main_fields) or "(nothing -- every field has its own)"),
            "key": "the per-record " + sym_name + " key, RSA-%d encrypted" % cfg["rsa_bits"],
            "extra": "ElGamal encryption of the " + (cfg["extra"]["label"] if cfg["extra"] else ""),
            "votes": "Paillier encryptions of a 0/1 per option (one-hot ballot)",
            "time": "timestamp YYYY-MM-DD HH:MM:SS",
            "hash": HASHES[cfg["hash"]] + " of the " + ("plaintext" if cfg["hash_over"] == "plaintext" else "id + ciphertexts + time"),
            "sig": SIGNATURES[sig] + " of " + sig_msg + (" with the SIGNER's own key" if user_keys else ""),
            "salt": "random salt for this record's password (PBKDF2)",
            "pwcheck": "check value of the password-derived key (the password is never stored)",
            "signer": "who signed (their own key pair verifies it)",
            "cosigs": "countersignatures  name:signature;name:signature  (over a hash of the signed message|sig)"}
    for f in fenc:
        alg_name = SYMMETRIC[f["alg"]][0] if f["alg"] in SYMMETRIC else ASYMMETRIC[f["alg"]]
        desc["f_" + f["var"]] = alg_name + " of " + f["label"] + " (its own algorithm)"
    scheme_desc = {"p": "Paillier encryption of %s (adds)", "m": "textbook-RSA encryption of %s (multiplies)",
                   "e": "ElGamal (c1,c2) of %s (multiplies)", "x": "exponential-ElGamal (c1,c2) of g^%s (adds)"}
    for op in ops:
        if op["type"] != "votes":
            desc[op["store"]] = scheme_desc[op["scheme"]] % op["label"]
    header = ["# %s  --  generated by reference/generate.py" % cfg["name"], "#",
              "# One record per line in %s_records.txt:" % prefix]
    header += ["#   %-10s %s" % (name, desc[name]) for name in stored]
    header += ["#"]
    for role, actions in cfg["roles"]:
        header.append("# %-18s: %s" % (role or "Menu", ", ".join(actions)))
    if index_fields:
        header += ["#", "# Indexes on %s: %s" % (", ".join(index_fields), ", ".join(cfg["methods"]))]
        header.append("#   (the plain index is stored in CLEAR -- it is the 'normal' index to compare with)")
    header += ["#",
               "# Verification ALWAYS happens before decryption."]
    if persist:
        header += ["# Keys are generated on the FIRST run and saved to %s_keys.txt; every later" % prefix,
                   "# run loads them, so records from earlier runs still verify and decrypt.",
                   "# Delete the keys file AND the records file to start completely fresh."]
    else:
        header += ["# Keys are generated at every start-up, so the data files are cleared at start",
                   "# (old records could not be verified with new keys anyway)."]
    if wrap_file:
        header.append("# The %s key is RSA-encrypted and saved to %s_wrapped_key.txt; decryption reads"
                      % (sym_name, prefix))
        header.append("# it back and recovers the key with the RSA private key.")
    if cfg["decrypted_file"] and "decrypt" in cfg["used"]:
        header.append("# Every successful decryption is appended to %s_decrypted.txt (history)." % prefix)
    if cfg["file_input"]:
        sep = cfg["import_separator"]
        header += ["# Inputs from a .txt file, no typing:",
                   "#   - menu action 'Import ... from a .txt file': one record per line, values separated",
                   "#     by '%s' in this order:  %s" % (sep, (" " + sep + " ").join(import_columns(cfg))),
                   "#     (blank lines and lines starting with # are skipped)",
                   "#   - python %s --answers answers.txt : every question is answered by the next"
                   % os.path.basename(cfg["out"]),
                   "#     line of the file; the keyboard takes over when it runs out."]
    if cfg["rules"]:
        header.append("# Field constraints (CONSTRAINTS): %s -- invalid input is asked again."
                      % ", ".join(sorted(cfg["rules"])))
    if login:
        header.append("# Every role menu starts with a username + password login (salted PBKDF2 in %s_users.txt)." % prefix)
    if password:
        header.append("# Each record has its OWN password: key = PBKDF2(password, salt); only salt + check are stored.")
    if user_keys:
        header.append("# Every signer has their OWN key pair (%s_signer_keys.txt); verification uses the signer's key." % prefix)
    if dwin:
        header.append("# Decryption is only allowed inside the %s (set at start-up)." % dwin)
    if sockets:
        header.append("# Socket mode: run 'python %s server' in one terminal and 'python %s client' in"
                      % (os.path.basename(cfg["out"]), os.path.basename(cfg["out"])))
        header.append("# another; the server verifies every record it receives and replies ACK / REJECTED.")
    header += ["# SHOW_STEPS = True prints every value computed (keys, ciphertexts, hashes, ...).",
               "# Lines marked TODO hold names/numbers to copy from the question.",
               "#",
               "# Run:  python %s         (menu)" % os.path.basename(cfg["out"]),
               "#       python %s test    (runs every action with typed-in answers)" % os.path.basename(cfg["out"])]
    if sockets:
        header += ["#       python %s server  /  python %s client" % (os.path.basename(cfg["out"]), os.path.basename(cfg["out"]))]

    # ---------------- constants ----------------
    index_files = []
    consts = ['HERE = os.path.dirname(os.path.abspath(__file__))',
              'RECORDS_FILE = os.path.join(HERE, "%s_records.txt")' % prefix,
              'LOG_FILE = os.path.join(HERE, "%s_access_log.txt")' % prefix]
    if persist:
        consts.append('KEYS_FILE = os.path.join(HERE, "%s_keys.txt")' % prefix)
    if wrap_file:
        consts.append('WRAPPED_KEY_FILE = os.path.join(HERE, "%s_wrapped_key.txt")' % prefix)
    if cfg["decrypted_file"] and "decrypt" in cfg["used"]:
        consts.append('DECRYPTED_FILE = os.path.join(HERE, "%s_decrypted.txt")' % prefix)
    if "report" in cfg["used"]:
        consts.append('REPORT_FILE = os.path.join(HERE, "%s_report.txt")' % prefix)
    if login:
        consts.append('USERS_FILE = os.path.join(HERE, "%s_users.txt")' % prefix)
    if user_keys and persist:
        consts.append('SIGNER_KEYS_FILE = os.path.join(HERE, "%s_signer_keys.txt")' % prefix)
    if index_fields:
        index_files.append("PLAIN_INDEX_FILE")
        consts.append('PLAIN_INDEX_FILE = os.path.join(HERE, "%s_plain_index.txt")' % prefix)
    if "sse" in types:
        index_files.append("SSE_INDEX_FILE")
        consts.append('SSE_INDEX_FILE = os.path.join(HERE, "%s_sse_index.txt")' % prefix)
    if "pkse" in types:
        index_files.append("PKSE_INDEX_FILE")
        consts.append('PKSE_INDEX_FILE = os.path.join(HERE, "%s_pkse_index.txt")' % prefix)
    consts += ["",
               "FIELDS = %s" % json.dumps(stored),
               "ID_LABEL = %s" % q(cfg["id_label"])]
    votes_op = [op for op in ops if op["type"] == "votes"]
    if votes_op:
        consts.append("CHOICES = %s      # TODO: the real candidates / options" % json.dumps(votes_op[0]["choices"]))
    if cfg["trustees"]:
        consts.append("TRUSTEES = %d       # private key split between this many trustees (all needed)" % cfg["trustees"])
    if index_fields:
        consts.append("INDEX_FIELDS = %s" % json.dumps(index_fields))
        consts.append("SEARCH_METHODS = %s" % json.dumps(cfg["methods"]))
    if "search_time" in cfg["used"]:
        consts.append("TIME_METHODS = %s" % json.dumps(cfg["time_methods"]))
    if login or user_keys:
        consts.append('CURRENT_USER = "-"  # the user logged in / signing')
    if sockets:
        consts += ['HOST = "127.0.0.1"', "PORT = 5000"]
    if cfg["rules"]:
        consts.append("CONSTRAINTS = %s      # CHANGE: the rules the question gives" % json.dumps(cfg["rules"]))
    if cfg["file_input"]:
        consts.append("IMPORT_COLUMNS = %s" % json.dumps(import_columns(cfg)))
        consts.append("IMPORT_SEPARATOR = %s      # CHANGE: separator used in the import file" % q(cfg["import_separator"]))
    consts += ['ROLE = "-"          # the role currently logged in (written to the access log)',
               "SHOW_STEPS = %s   # chosen in generate.py: print every value computed" % bool(cfg["show_steps"])]
    prog.add("\n".join(consts), "import os", "import sys")

    # ---------------- verbatim cipher functions ----------------
    prog.use("glue_snippets.py", "timestamp")
    prog.need("from datetime import datetime, timedelta")
    if (sym and cfg["key_src"] in ("typed_once", "typed_each")) or cfg["iv_src"] == "typed":
        prog.use("glue_snippets.py", "normalize_bytes")
    if sig == "elgamal":
        prog.use("elgamal_signature.py", "_hash_to_int", "elgamal_generate_keys", "elgamal_sign", "elgamal_verify", "_egcd",
                 "_split_signature")
    if sig == "schnorr":
        prog.use("schnorr_signature.py", "_hash_to_int", "schnorr_generate_domain_parameters",
                 "schnorr_generate_keys", "schnorr_sign", "schnorr_verify", "_split_signature")
    if sig == "dsa":
        prog.use("dh_signature.py", "_hash_to_int", "dh_generate_domain_parameters", "dh_generate_keys", "dh_sign", "dh_verify",
                 "_split_signature")
    if enc in ("aes128", "aes192", "aes256") or "sse" in types:
        prog.use("aes.py", "aes_encrypt", "aes_decrypt")
    if enc == "des":
        prog.use("block_modes.py", "ALGORITHMS", "PADDED_MODES", "_to_bytes", "_new_cipher", "block_encrypt", "block_decrypt")
    if enc == "3des":
        prog.use("tripledes.py", "_split_key", "_ede_encrypt_block", "_ede_decrypt_block", "tripledes_encrypt", "tripledes_decrypt")
    if need_rsa:
        names = ["rsa_generate_keys"] + (["rsa_encrypt", "rsa_decrypt"] if enc == "rsa" or wrap or wrap_file else [])
        patch = None
        if cfg["rsa_bits"] != 2048:
            patch = ("key_size=2048", "key_size=%d     # RSA-%d as the question asks" % (cfg["rsa_bits"], cfg["rsa_bits"]))
        prog.use("rsa.py", *names, patch=patch)
    if sig == "rsa":
        prog.use("rsa_signature.py", "rsa_message_number", "rsa_sign", "rsa_verify")
    if enc == "elgamal" or cfg["extra"]:
        names = ["elgamal_encrypt", "elgamal_decrypt"]
        if (enc == "elgamal" and not cfg["elgamal_given"]) or (cfg["extra"] and not cfg["extra"].get("given")):
            names.insert(0, "elgamal_generate_keys")
        prog.use("elgamal.py", *names)
    if enc == "ecc":
        prog.use("ecc.py", "ecc_generate_keys", "derive_shared_key", "ecc_encrypt", "ecc_decrypt")
    if enc == "rabin":
        prog.use("rabin.py", "_prime_3_mod_4", "rabin_generate_keys", "rabin_encrypt", "rabin_decrypt")
    prog.use("hashing.py", cfg["hash"] + "_hash")
    if need_paillier:
        names = ["paillier_generate_keys", "paillier_encrypt", "paillier_decrypt", "paillier_add"]
        if "pkse" in types or "p" in schemes:
            names += ["paillier_add_plain", "paillier_subtract", "paillier_multiply_plain"]
        prog.use("paillier.py", *names)
        if any(op["type"] == "compare" for op in ops):
            prog.need("from Crypto.Util.number import getRandomRange")
    if cfg["trustees"]:
        prog.use("threshold_paillier.py", "threshold_split_key", "threshold_partial_decrypt", "threshold_combine")
    if need_rsa_he:
        prog.use("rsa_homomorphic.py", "rsa_he_generate_keys", "rsa_he_encrypt", "rsa_he_decrypt", "rsa_he_multiply",
                 "rsa_he_multiply_plain", "rsa_he_power")
    if need_eg_he:
        prog.use("elgamal_homomorphic.py", "elgamal_he_generate_keys", "elgamal_he_encrypt", "elgamal_he_decrypt",
                 "elgamal_he_multiply", "elgamal_he_multiply_plain", "elgamal_he_power",
                 "elgamal_exp_encrypt", "elgamal_exp_decrypt")
    if "sse" in types:
        prog.use("sse.py", "sse_generate_key", "sse_trapdoor")
    if "pkse" in types:
        prog.use("pkse.py", "_word_number", "_text_to_number", "_number_to_text")
        prog.need("from Crypto.Util.number import getRandomRange")

    for alg in sorted(falgs):
        if alg in ("aes128", "aes192", "aes256"):
            prog.use("aes.py", "aes_encrypt", "aes_decrypt")
        elif alg == "des":
            prog.use("block_modes.py", "ALGORITHMS", "PADDED_MODES", "_to_bytes", "_new_cipher", "block_encrypt", "block_decrypt")
        elif alg == "3des":
            prog.use("tripledes.py", "_split_key", "_ede_encrypt_block", "_ede_decrypt_block", "tripledes_encrypt",
                     "tripledes_decrypt")
        elif alg == "rsa":
            prog.use("rsa.py", "rsa_encrypt", "rsa_decrypt")
        elif alg == "elgamal":
            prog.use("elgamal.py", "elgamal_generate_keys", "elgamal_encrypt", "elgamal_decrypt")
        elif alg == "ecc":
            prog.use("ecc.py", "ecc_generate_keys", "derive_shared_key", "ecc_encrypt", "ecc_decrypt")
        elif alg == "rabin":
            prog.use("rabin.py", "_prime_3_mod_4", "rabin_generate_keys", "rabin_encrypt", "rabin_decrypt")
        if alg in SYMMETRIC:
            prog.need("from Crypto.Random import get_random_bytes")
    if password or login:
        prog.need("import hashlib")
    if login:
        prog.need("import hmac")
    if sockets:
        prog.need("import socket")

    # ---------------- show every calculation ----------------
    prog.add(block(r'''
        # ---------- output formatting ----------

        WRAP = 64          # long values (hex, big numbers) are printed in lines of this many characters


        def wrap_value(value, indent):
            """Cuts a long value into WRAP-character lines; every extra line starts at column `indent`."""
            lines = []
            for line in str(value).split("\n"):
                lines += [line[i:i + WRAP] for i in range(0, len(line), WRAP)] or [""]
            return ("\n" + " " * indent).join(lines)


        def section(title):
            print()
            print("  " + title.upper())
            print("  " + "-" * len(title))


        def show_value(name, value, width=24):
            """One aligned 'name : value' line; a long value wraps under itself."""
            print("  " + name.ljust(width) + " : " + wrap_value(value, width + 5))


        def step(name, value):
            """One intermediate value (only when SHOW_STEPS is on): the name, the value indented below it."""
            if SHOW_STEPS:
                print("    > " + name)
                print("        " + wrap_value(value, 8))
                print()


        def result_line(text):
            print()
            print("  ==> " + text)
    '''))

    # ---------------- keys ----------------
    setup = ["# ---------- keys: generated ONCE at start-up ----------", "",
             "K = {}", "", "", "def setup_keys():"]
    if user_keys and persist:
        setup.append("    load_user_keys()                  # every signer's own key pair (kept between runs)")
    if persist:
        setup += ["    if os.path.exists(KEYS_FILE):",
                  "        load_keys()",
                  '        print("Keys loaded from", KEYS_FILE, "-- the same keys as the earlier runs.")',
                  "        return"]
    setup.append('    print("Generating keys (a few seconds)...")')
    size = SYMMETRIC[enc][1] if sym else 0
    if sym and cfg["key_src"] == "random":
        setup.append('    K["sym"] = get_random_bytes(%d)' % size)
        setup.append('    print("%s key (hex):", K["sym"].hex())' % sym_name)
        prog.need("from Crypto.Random import get_random_bytes")
    if sym and cfg["key_src"] == "typed_once":
        setup.append('    K["sym"] = normalize_bytes(input("%s key (any text, fitted to %d bytes): "), %d)' % (sym_name, size, size))
        setup.append('    print("%s key (hex):", K["sym"].hex())' % sym_name)
    if wrap:
        prog.need("from Crypto.Random import get_random_bytes")
    if need_rsa:
        setup.append('    K["rsa_priv"], K["rsa_pub"], K["rsa_n"], K["rsa_e"], K["rsa_d"] = rsa_generate_keys()')
        setup.append('    print("RSA public key: n =", K["rsa_n"], " e =", K["rsa_e"])')
    if enc == "elgamal":
        if cfg["elgamal_given"]:
            p, g, x = cfg["elgamal_given"]
            setup.append('    K["el_p"], K["el_g"], K["el_x"] = %d, %d, %d      # TODO: p, g, x from the question' % (p, g, x))
            setup.append('    K["el_h"] = pow(K["el_g"], K["el_x"], K["el_p"])')
        else:
            setup.append('    K["el_p"], K["el_g"], K["el_h"], K["el_x"] = elgamal_generate_keys()')
        setup.append('    print("ElGamal public key: p =", K["el_p"], " g =", K["el_g"], " h =", K["el_h"])')
    if cfg["extra"]:
        if cfg["extra"].get("given"):
            p, g, x = cfg["extra"]["given"]
            setup.append('    K["ex_p"], K["ex_g"], K["ex_x"] = %d, %d, %d      # TODO: p, g, x from the question' % (p, g, x))
            setup.append('    K["ex_h"] = pow(K["ex_g"], K["ex_x"], K["ex_p"])')
        else:
            setup.append('    K["ex_p"], K["ex_g"], K["ex_h"], K["ex_x"] = elgamal_generate_keys()')
        setup.append('    print("ElGamal for the %s: p =", K["ex_p"], " g =", K["ex_g"], " h =", K["ex_h"])'
                     % cfg["extra"]["label"].lower())
    if sig == "elgamal":
        setup.append('    K["sg_p"], K["sg_g"], K["sg_y"], K["sg_x"] = elgamal_generate_keys()')
        setup.append('    print("ElGamal signature public key: p =", K["sg_p"], " g =", K["sg_g"], " y =", K["sg_y"])')
    if sig == "schnorr":
        setup.append('    K["sc_p"], K["sc_q"], K["sc_g"] = schnorr_generate_domain_parameters()')
        setup.append('    K["sc_y"], K["sc_x"] = schnorr_generate_keys(K["sc_p"], K["sc_q"], K["sc_g"])')
        setup.append('    print("Schnorr: p =", K["sc_p"], " q =", K["sc_q"], " g =", K["sc_g"], " y =", K["sc_y"])')
    if sig == "dsa":
        setup.append('    K["ds_p"], K["ds_q"], K["ds_g"] = dh_generate_domain_parameters()')
        setup.append('    K["ds_y"], K["ds_x"] = dh_generate_keys(K["ds_p"], K["ds_q"], K["ds_g"])')
        setup.append('    print("DSA: p =", K["ds_p"], " q =", K["ds_q"], " g =", K["ds_g"], " y =", K["ds_y"])')
    if enc == "ecc":
        setup.append('    K["ecc_priv"], K["ecc_pub"] = ecc_generate_keys()')
    if enc == "rabin":
        setup.append('    K["rabin_n"], (K["rabin_p"], K["rabin_q"]) = rabin_generate_keys()')
        setup.append('    print("Rabin public key n =", K["rabin_n"])')
    if need_paillier:
        setup.append('    K["p_n"], K["p_g"], K["p_lam"], K["p_mu"] = paillier_generate_keys(1024)')
        setup.append('    print("Paillier public key: n =", K["p_n"], " g = n + 1")')
    if cfg["trustees"]:
        setup.append('    K["shares"] = threshold_split_key(K["p_n"], K["p_lam"], K["p_mu"], TRUSTEES)')
        setup.append('    print("Paillier private key split into", TRUSTEES, "trustee shares")')
    if need_rsa_he:
        setup.append('    K["he_n"], K["he_e"], K["he_d"] = rsa_he_generate_keys()')
        setup.append('    print("Textbook RSA (multiplicative) public key: n =", K["he_n"], " e =", K["he_e"])')
    if need_eg_he:
        setup.append('    K["eg_p"], K["eg_g"], K["eg_h"], K["eg_x"] = elgamal_he_generate_keys()')
        setup.append('    print("ElGamal (homomorphic) public key: p =", K["eg_p"], " g =", K["eg_g"], " h =", K["eg_h"])')
    if "sse" in types:
        setup.append('    K["sse"] = sse_generate_key()')
        setup.append('    print("SSE key (hex):", K["sse"].hex())')
    if cfg["window"]:
        w = cfg["window"][0].upper() + cfg["window"][1:]
        setup += ['    now = datetime.now()',
                  '    print("%s (press Enter for: from now, for 24 hours)")' % w,
                  '    K["start"] = ask_time("  start (YYYY-MM-DD HH:MM): ", now.strftime("%Y-%m-%d %H:%M"))',
                  '    K["end"] = ask_time("  end   (YYYY-MM-DD HH:MM): ", (now + timedelta(days=1)).strftime("%Y-%m-%d %H:%M"))',
                  '    print("%s:", K["start"], "to", K["end"])' % w]
    for f in fenc:
        if f["alg"] in SYMMETRIC:
            setup.append('    K["fk_%s"] = get_random_bytes(%d)          # own key for the %s field'
                         % (f["var"], SYMMETRIC[f["alg"]][1], f["label"]))
            setup.append('    print("%s key for %s (hex):", K["fk_%s"].hex())' % (SYMMETRIC[f["alg"]][0].split("-CBC")[0],
                                                                                  f["label"], f["var"]))
    if "elgamal" in falgs and enc != "elgamal":
        setup.append('    K["el_p"], K["el_g"], K["el_h"], K["el_x"] = elgamal_generate_keys()')
        setup.append('    print("ElGamal public key: p =", K["el_p"], " g =", K["el_g"], " h =", K["el_h"])')
    if "ecc" in falgs and enc != "ecc":
        setup.append('    K["ecc_priv"], K["ecc_pub"] = ecc_generate_keys()')
    if "rabin" in falgs and enc != "rabin":
        setup.append('    K["rabin_n"], (K["rabin_p"], K["rabin_q"]) = rabin_generate_keys()')
        setup.append('    print("Rabin public key n =", K["rabin_n"])')
    if dwin:
        w = dwin[0].upper() + dwin[1:]
        setup += ['    now = datetime.now()',
                  '    print("%s -- decryption allowed only inside it (Enter: from now, for 24 hours)")' % w,
                  '    K["dstart"] = ask_time("  start (YYYY-MM-DD HH:MM): ", now.strftime("%Y-%m-%d %H:%M"))',
                  '    K["dend"] = ask_time("  end   (YYYY-MM-DD HH:MM): ", (now + timedelta(days=1)).strftime("%Y-%m-%d %H:%M"))',
                  '    print("%s:", K["dstart"], "to", K["dend"])' % w]
    if wrap_file:
        setup += ['    wrapped = rsa_encrypt(K["rsa_pub"], K["sym"].hex())',
                  '    with open(WRAPPED_KEY_FILE, "w", encoding="utf-8") as f:',
                  "        f.write(wrapped)",
                  '    step("%s key encrypted with the RSA public key", wrapped)' % sym_name,
                  '    print("%s key RSA-encrypted and saved to", WRAPPED_KEY_FILE)' % sym_name]
    if persist:
        setup += ["    save_keys()", '    print("Keys saved to", KEYS_FILE, "-- later runs reuse them.")']
    setup.append('    print("Keys ready.")')
    if persist:
        key_names = []
        for line in setup:
            # names assigned in setup lines: K["a"], K["b"] = ...   or   K["a"] = ...
            if line.lstrip().startswith("K[") and " = " in line:
                for name in re.findall(r'K\["(\w+)"\]', line.split(" = ")[0]):
                    if not name.endswith("_pub") and name not in key_names:
                        key_names.append(name)
        if need_rsa or enc == "ecc":
            prog.need("from cryptography.hazmat.primitives import serialization")
        prog.add(fill(r'''
            # ---------- persistent keys: one name=type:value per line in KEYS_FILE ----------
            # Public keys are not stored; they are rebuilt from the private keys.

            KEY_NAMES = {{names}}


            def save_keys():
                with open(KEYS_FILE, "w", encoding="utf-8") as f:
                    for name, value in K.items():
                        if name.endswith("_pub"):
                            continue
                        if isinstance(value, bytes):
                            kind, text = "hex", value.hex()
                        elif isinstance(value, int):
                            kind, text = "int", str(value)
                        elif isinstance(value, str):
                            kind, text = "str", value
                        elif isinstance(value, list):
                            kind, text = "ints", ",".join(str(v) for v in value)
                        else:                                   # an RSA / ECC private key object
                            kind = "pem"
                            text = value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()).hex()
                        f.write(name + "=" + kind + ":" + text + "\n")


            def load_keys():
                with open(KEYS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        name, rest = line.rstrip("\n").split("=", 1)
                        kind, text = rest.split(":", 1)
                        if kind == "hex":
                            K[name] = bytes.fromhex(text)
                        elif kind == "int":
                            K[name] = int(text)
                        elif kind == "str":
                            K[name] = text
                        elif kind == "ints":
                            K[name] = [int(v) for v in text.split(",")]
                        else:
                            K[name] = serialization.load_pem_private_key(bytes.fromhex(text), password=None)
                for name in list(K):
                    if name.endswith("_priv"):
                        K[name[:-len("_priv")] + "_pub"] = K[name].public_key()
                missing = [name for name in KEY_NAMES if name not in K]
                if missing:
                    sys.exit("The keys file is from a different version of this program (missing "
                             + ", ".join(missing) + "). Delete " + KEYS_FILE + " and the records file.")
        ''', names=json.dumps(key_names)))
    prog.add("\n".join(setup))

    # ---------------- crypto zone ----------------
    z = ["# ==================== EDIT ZONE 1: which crypto ====================",
         "# Every crypto call goes through these functions. Stored values are",
         "# strings, so int() happens HERE only.", ""]

    z.append("def encrypt_data(plaintext):")
    z.append('    """%s. Returns the fields to store."""' % enc_name)
    if sym:
        key_line = {"random": 'key = K["sym"]',
                    "wrap": 'key = get_random_bytes(%d)                  # fresh key for every record' % size,
                    "typed_once": 'key = K["sym"]',
                    "typed_each": 'key = normalize_bytes(input("%s key (any text): "), %d)' % (sym_name, size),
                    "password": 'password = input("Password for this record: ")\n'
                                '    salt = os.urandom(16)\n'
                                '    step("random salt (stored in the record)", salt.hex())\n'
                                '    key = password_key(password, salt, %d)              # PBKDF2' % size}[cfg["key_src"]]
        z.append("    " + key_line)
        z.append('    step("%s key (hex)", key.hex())' % sym_name)
        iv_size = 8 if enc == "des" else 16
        if cfg["iv_src"] == "typed":
            z.append('    iv = normalize_bytes(input("IV (any text, fitted to %d bytes): "), %d)' % (iv_size, iv_size))
        elif enc != "3des":
            z.append("    iv = None                                   # None -> a fresh random IV")
        call = {"aes128": "aes_encrypt(key, plaintext, iv)", "aes192": "aes_encrypt(key, plaintext, iv)",
                "aes256": "aes_encrypt(key, plaintext, iv)", "des": 'block_encrypt("des", "cbc", key, plaintext, iv)',
                "3des": "tripledes_encrypt(key.hex(), plaintext)"}[enc]
        z.append("    ciphertext = " + call)
        if enc != "3des":
            z.append('    step("IV (hex) = first %d hex chars of the ciphertext", ciphertext[:%d])' % (iv_size * 2, iv_size * 2))
        z.append('    step("%s ciphertext (hex)", ciphertext)' % enc_name)
        z.append('    fields = {"enc": ciphertext}')
        if password:
            z += ['    fields["salt"] = salt.hex()',
                  '    fields["pwcheck"] = password_check(key)',
                  '    step("password check value (stored instead of the password)", fields["pwcheck"])']
        if wrap:
            z.append('    fields["key"] = rsa_encrypt(K["rsa_pub"], key.hex())    # RSA-wrapped key')
            z.append('    step("%s key encrypted with the RSA public key", fields["key"])' % sym_name)
        z.append("    return fields")
    else:
        call = {"rsa": 'rsa_encrypt(K["rsa_pub"], plaintext)',
                "elgamal": 'elgamal_encrypt(K["el_p"], K["el_g"], K["el_h"], plaintext)',
                "ecc": 'ecc_encrypt(K["ecc_pub"], plaintext)',
                "rabin": 'rabin_encrypt(K["rabin_n"], plaintext)'}[enc]
        z += ["    ciphertext = " + call, '    step("%s ciphertext", ciphertext)' % enc_name, '    return {"enc": ciphertext}']
    z += ["", ""]
    z.append("def decrypt_data(rec, show=True):")
    if sym:
        key_line = {"random": 'key = K["sym"]',
                    "wrap": 'key = bytes.fromhex(rsa_decrypt(K["rsa_priv"], rec["key"]))    # unwrap the key first',
                    "typed_once": 'key = K["sym"]',
                    "typed_each": 'key = normalize_bytes(input("%s key (any text): "), %d)' % (sym_name, size),
                    "password": 'password = input("Password for this record: ")\n'
                                '    key = password_key(password, bytes.fromhex(rec["salt"]), %d)\n'
                                '    if password_check(key) != rec["pwcheck"]:\n'
                                '        raise ValueError("wrong password for this record")' % size}[cfg["key_src"]]
        if wrap_file:
            z += ['    with open(WRAPPED_KEY_FILE, "r", encoding="utf-8") as f:',
                  "        wrapped = f.read().strip()",
                  '    key = bytes.fromhex(rsa_decrypt(K["rsa_priv"], wrapped))    # unwrap the key first']
        else:
            z.append("    " + key_line)
        z += ["    if show:"]
        if wrap_file:
            z.append('        step("RSA-encrypted key read from " + WRAPPED_KEY_FILE, wrapped)')
        z.append('        step("%s key %s (hex)", key.hex())'
                 % (sym_name, "recovered with the RSA private key" if wrap or wrap_file else "used"))
        call = {"aes128": 'aes_decrypt(key, rec["enc"])', "aes192": 'aes_decrypt(key, rec["enc"])',
                "aes256": 'aes_decrypt(key, rec["enc"])', "des": 'block_decrypt("des", "cbc", key, rec["enc"])',
                "3des": 'tripledes_decrypt(key.hex(), rec["enc"])'}[enc]
    else:
        call = {"rsa": 'rsa_decrypt(K["rsa_priv"], rec["enc"])',
                "elgamal": 'elgamal_decrypt(K["el_p"], K["el_x"], rec["enc"])',
                "ecc": 'ecc_decrypt(K["ecc_priv"], rec["enc"])',
                "rabin": 'rabin_decrypt(K["rabin_n"], K["rabin_p"], K["rabin_q"], rec["enc"])'}[enc]
    z += ["    plaintext = " + call, "    if show:", '        step("decrypted plaintext", plaintext)', "    return plaintext", "", ""]

    if cfg["extra"]:
        z += ["def encrypt_extra(text):",
              '    ciphertext = elgamal_encrypt(K["ex_p"], K["ex_g"], K["ex_h"], text)',
              '    step("ElGamal ciphertext of the %s (c1:c2 per character)", ciphertext)' % cfg["extra"]["label"].lower(),
              "    return ciphertext", "", "",
              "def decrypt_extra(ciphertext):",
              '    return elgamal_decrypt(K["ex_p"], K["ex_x"], ciphertext)', "", ""]

    if password:
        z += ["def password_key(password, salt, size):",
              '    """PBKDF2-HMAC-SHA256: password + salt -> a key of `size` bytes. The password is never stored."""',
              '    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, dklen=size)', "", "",
              "def password_check(key):",
              '    """Stored instead of the password: a wrong password is detected BEFORE decrypting."""',
              '    return hashlib.sha256(b"check" + key).hexdigest()', "", ""]
    field_calls = {
        "aes128": ('aes_encrypt(K["fk_{v}"], text)', 'aes_decrypt(K["fk_{v}"], ciphertext)'),
        "aes192": ('aes_encrypt(K["fk_{v}"], text)', 'aes_decrypt(K["fk_{v}"], ciphertext)'),
        "aes256": ('aes_encrypt(K["fk_{v}"], text)', 'aes_decrypt(K["fk_{v}"], ciphertext)'),
        "des": ('block_encrypt("des", "cbc", K["fk_{v}"], text)', 'block_decrypt("des", "cbc", K["fk_{v}"], ciphertext)'),
        "3des": ('tripledes_encrypt(K["fk_{v}"].hex(), text)', 'tripledes_decrypt(K["fk_{v}"].hex(), ciphertext)'),
        "rsa": ('rsa_encrypt(K["rsa_pub"], text)', 'rsa_decrypt(K["rsa_priv"], ciphertext)'),
        "elgamal": ('elgamal_encrypt(K["el_p"], K["el_g"], K["el_h"], text)', 'elgamal_decrypt(K["el_p"], K["el_x"], ciphertext)'),
        "ecc": ('ecc_encrypt(K["ecc_pub"], text)', 'ecc_decrypt(K["ecc_priv"], ciphertext)'),
        "rabin": ('rabin_encrypt(K["rabin_n"], text)', 'rabin_decrypt(K["rabin_n"], K["rabin_p"], K["rabin_q"], ciphertext)')}
    for f in fenc:
        e_call, d_call = field_calls[f["alg"]]
        alg_name = SYMMETRIC[f["alg"]][0] if f["alg"] in SYMMETRIC else ASYMMETRIC[f["alg"]]
        z += ["def encrypt_field_%s(text):" % f["var"],
              '    """The %s field has its OWN algorithm: %s."""' % (f["label"], alg_name),
              "    ciphertext = " + e_call.replace("{v}", f["var"]),
              '    step("%s ciphertext of %s", ciphertext)' % (alg_name, f["label"]),
              "    return ciphertext", "", "",
              "def decrypt_field_%s(ciphertext, show=True):" % f["var"],
              "    text = " + d_call.replace("{v}", f["var"]),
              "    if show:",
              '        step("%s decrypted (%s)", text)' % (f["label"], alg_name),
              "    return text", "", ""]
    if fenc:
        z += ["def decrypt_all(rec, show=True):",
              '    """The main ciphertext plus every separately encrypted field, as one text."""',
              "    parts = [decrypt_data(rec, show)]        # always included, so the hash covers every ciphertext"]
        for f in fenc:
            z.append('    parts.append(%s + decrypt_field_%s(rec["f_%s"], show))' % (q(f["label"] + ": "), f["var"], f["var"]))
        z += ['    return "\\n".join(parts)', "", ""]

    z += ["def hash_fn(text):", "    return %s_hash(text)" % cfg["hash"], "", ""]

    if sig != "none":
        sign_call = {"rsa": 'rsa_sign(message, K["rsa_d"], K["rsa_n"])',
                     "elgamal": 'elgamal_sign(message, K["sg_p"], K["sg_g"], K["sg_x"])',
                     "schnorr": 'schnorr_sign(message, K["sc_p"], K["sc_q"], K["sc_g"], K["sc_x"])',
                     "dsa": 'dh_sign(message, K["ds_p"], K["ds_q"], K["ds_g"], K["ds_x"])'}[sig]
        verify_call = {"rsa": 'rsa_verify(message, signature, K["rsa_e"], K["rsa_n"])',
                       "elgamal": 'elgamal_verify(message, signature, K["sg_p"], K["sg_g"], K["sg_y"])',
                       "schnorr": 'schnorr_verify(message, signature, K["sc_p"], K["sc_q"], K["sc_g"], K["sc_y"])',
                       "dsa": 'dh_verify(message, signature, K["ds_p"], K["ds_q"], K["ds_g"], K["ds_y"])'}[sig]
        z += ["def sign(message):", "    return " + sign_call, "", "",
              "def verify_sig(signature, message, show=False):"]
        if sig == "rsa":
            z += ["    if show:",
                  '        step("signature^e mod n (with the public key)", pow(int(signature), K["rsa_e"], K["rsa_n"]))',
                  '        step("SHA-256 of the message mod n (must be equal)", rsa_message_number(message, K["rsa_n"]))']
        z += ["    return " + verify_call, "", ""]

    if user_keys:
        new_keys = {"rsa": ["    _, _, n, e, d = rsa_generate_keys()", "    return [n, e, d]"],
                    "elgamal": ["    return list(elgamal_generate_keys())                 # [p, g, y, x]"],
                    "schnorr": ["    p, q, g = schnorr_generate_domain_parameters()",
                                "    y, x = schnorr_generate_keys(p, q, g)", "    return [p, q, g, y, x]"],
                    "dsa": ["    p, q, g = dh_generate_domain_parameters()",
                            "    y, x = dh_generate_keys(p, q, g)", "    return [p, q, g, y, x]"]}[sig]
        sign_body = {"rsa": ['    return rsa_sign(message, keys[2], keys[0])'],
                     "elgamal": ['    return elgamal_sign(message, keys[0], keys[1], keys[3])'],
                     "schnorr": ['    return schnorr_sign(message, keys[0], keys[1], keys[2], keys[4])'],
                     "dsa": ['    return dh_sign(message, keys[0], keys[1], keys[2], keys[4])']}[sig]
        verify_body = {"rsa": ["    if show:",
                               '        step("signature^e mod n (signer\'s public key)", pow(int(signature), keys[1], keys[0]))',
                               '        step("SHA-256 of the message mod n (must be equal)", rsa_message_number(message, keys[0]))',
                               "    return rsa_verify(message, signature, keys[1], keys[0])"],
                       "elgamal": ["    return elgamal_verify(message, signature, keys[0], keys[1], keys[2])"],
                       "schnorr": ["    return schnorr_verify(message, signature, keys[0], keys[1], keys[2], keys[3])"],
                       "dsa": ["    return dh_verify(message, signature, keys[0], keys[1], keys[2], keys[3])"]}[sig]
        public = {"rsa": "keys[:2]          # (n, e)", "elgamal": "keys[:3]          # (p, g, y)",
                  "schnorr": "keys[:4]          # (p, q, g, y)", "dsa": "keys[:4]          # (p, q, g, y)"}[sig]
        z += ["# ---------- every signer has their OWN key pair ----------", "",
              "USER_KEYS = {}      # signer name -> list of ints (their key pair)", "", "",
              "def new_user_keys():"] + new_keys + ["", "",
              "def public_part(keys):", "    return " + public, "", "",
              "def sign_with(keys, message):"] + sign_body + ["", "",
              "def verify_with(keys, signature, message, show=False):"] + verify_body + ["", ""]
        if persist:
            z += ["def save_user_keys():",
                  '    with open(SIGNER_KEYS_FILE, "w", encoding="utf-8") as f:',
                  "        for name, keys in USER_KEYS.items():",
                  '            f.write(name + "|" + ",".join(str(k) for k in keys) + "\\n")', "", "",
                  "def load_user_keys():",
                  "    if os.path.exists(SIGNER_KEYS_FILE):",
                  '        with open(SIGNER_KEYS_FILE, "r", encoding="utf-8") as f:',
                  "            for line in f:",
                  '                name, numbers = line.rstrip("\\n").split("|")',
                  '                USER_KEYS[name] = [int(k) for k in numbers.split(",")]', "", ""]
        else:
            z += ["def save_user_keys():", '    """Keys are not kept between runs in this program."""', "    return", "", "",
                  "def load_user_keys():", "    return", "", ""]
        z += ["def keys_of(name, create=False):",
              '    """The key pair of a signer; a new user gets a fresh pair when they first sign."""',
              "    if name not in USER_KEYS:",
              "        load_user_keys()                   # another program (e.g. the client) may have added it",
              "    if name not in USER_KEYS:",
              "        if not create:",
              "            return None",
              "        USER_KEYS[name] = new_user_keys()",
              "        save_user_keys()",
              '        print("New %s key pair generated for", name)' % SIGNATURES[sig].split(" signature")[0],
              '        step("public key of " + name, public_part(USER_KEYS[name]))',
              "    return USER_KEYS[name]", "", "",
              "def sign_as(name, message):",
              "    return sign_with(keys_of(name, create=True), message)", "", "",
              "def verify_as(name, signature, message, show=False):",
              "    keys = keys_of(name)",
              "    if keys is None:",
              "        if show:",
              '            step("no key pair known for", name)',
              "        return False",
              "    if show:",
              '        step("public key of " + name, public_part(keys))',
              "    return verify_with(keys, signature, message, show)", "", "",
              "def current_signer():"]
        if login:
            z += ['    """The logged-in user signs with their own key."""', "    return CURRENT_USER", "", ""]
        else:
            z += ["    while True:",
                  '        name = ask_text("Your name (your own key signs): ")',
                  '        if ":" not in name and ";" not in name:',
                  "            return name",
                  "        print(\"A name must not contain ':' or ';'.\")", "", ""]

    if any(op["scheme"] == "p" and op["type"] != "votes" for op in ops):
        z += ["def he_encrypt_add(x):",
              '    """Paillier: Enc(a) * Enc(b) mod n^2 = Enc(a + b)."""',
              '    return str(paillier_encrypt(K["p_n"], K["p_g"], x))', "", ""]
    if need_rsa_he:
        z += ["def he_encrypt_mul(x):",
              '    """Textbook RSA: Enc(a) * Enc(b) mod n = Enc(a * b)."""',
              '    return str(rsa_he_encrypt(K["he_n"], K["he_e"], x))', "", ""]
    if need_eg_he:
        z += ["def eg_text(ciphertext):", '    return str(ciphertext[0]) + "," + str(ciphertext[1])', "", "",
              "def eg_parse(text):", '    c1, c2 = text.split(",")', "    return int(c1), int(c2)", "", ""]
    if "e" in schemes:
        z += ["def he_encrypt_eg(x):",
              '    """ElGamal: (c1*c1\', c2*c2\') mod p = Enc(a * b). x must be 1 .. p-1."""',
              '    return eg_text(elgamal_he_encrypt(K["eg_p"], K["eg_g"], K["eg_h"], x))', "", ""]
    if "x" in schemes:
        z += ["def he_encrypt_egx(x):",
              '    """Exponential ElGamal: encrypts g^x, so Enc(g^a) * Enc(g^b) = Enc(g^(a+b))."""',
              '    return eg_text(elgamal_exp_encrypt(K["eg_p"], K["eg_g"], K["eg_h"], x))', "", ""]
    if votes_op:
        z += ["def encrypt_vote(choice):",
              '    """One-hot ballot: Enc(1) for the chosen option, Enc(0) for every other one."""',
              '    return ";".join(str(paillier_encrypt(K["p_n"], K["p_g"], 1 if c == choice else 0)) for c in CHOICES)',
              "", ""]
    if "p" in schemes:
        z.append("def decrypt_total(total):")
        if cfg["trustees"]:
            z += ['    """Threshold decryption: every trustee uses only its OWN share."""',
                  "    partials = []",
                  '    for number, share in enumerate(K["shares"], start=1):',
                  '        partial = threshold_partial_decrypt(K["p_n"], total, share)',
                  '        step("trustee " + str(number) + " partial decryption c^share mod n^2", partial)',
                  "        partials.append(partial)",
                  '    result = threshold_combine(K["p_n"], partials)',
                  '    step("all partials multiplied -> (product - 1) // n", result)',
                  "    return result"]
        else:
            z += ['    result = paillier_decrypt(K["p_n"], K["p_lam"], K["p_mu"], total)',
                  '    step("Paillier decryption L(c^lambda mod n^2) * mu mod n", result)',
                  "    return result"]
        z += ["", ""]

    z += ["# ==================== EDIT ZONE 2: what is hashed and signed ====================", ""]
    z += ["def hashed_part(rec):",
          '    """Everything except hash and signature -> changing ANY stored value is detected."""',
          '    return "|".join(rec[name] for name in FIELDS if name not in %s)'
          % ('("hash", "sig", "cosigs")' if cosign else '("hash", "sig")'), "", ""]
    if cfg["hash_over"] == "plaintext":
        z += ["def recompute_hash(rec, show=False):",
              '    """The hash is of the PLAINTEXT, so the receiver decrypts and hashes again.',
              '    The plaintext is NOT printed here -- only after every check has passed."""',
              "    if show:",
              '        step("recomputing the hash", "decrypting silently (plaintext shown only if every check passes)")',
              "    return hash_fn(%s(rec, False))" % ("decrypt_all" if fenc else "decrypt_data"), "", ""]
    else:
        z += ["def recompute_hash(rec, show=False):", "    data = hashed_part(rec)", "    if show:",
              '        step("data hashed (id|ciphertexts|time)", data)', "    return hash_fn(data)", "", ""]
    if sig != "none":
        if cfg["sign_time"]:
            z += ["def signed_part(rec):", '    """The signature covers the hash AND the timestamp (trusted timestamp)."""',
                  '    return rec["hash"] + "|" + rec["time"]', "", ""]
        else:
            z += ["def signed_part(rec):",
                  '    """Only the hash is signed.%s"""' % (
                      " The timestamp is still protected: it is part of the hashed data." if cfg["hash_over"] != "plaintext"
                      else " NOTE: the hash is of the plaintext, so the timestamp is NOT protected\n"
                           "    by hash or signature -- return rec[\"hash\"] + \"|\" + rec[\"time\"] to sign it too."),
                  '    return rec["hash"]', "", ""]
    if cosign:
        z += ["def cosign_message(rec):",
              '    """A countersignature covers the first signature too -- hashed, so it fits any signature scheme."""',
              '    return hash_fn(signed_part(rec) + "|" + rec["sig"])', "", ""]
    z += ["def check_record(rec, show=False):",
          '    """{check name: True/False} -- never raises. show=True prints every value compared."""',
          "    result = {}",
          "    try:",
          "        recomputed = recompute_hash(rec, show)",
          '        result["hash"] = recomputed == rec["hash"]',
          "    except Exception as e:",
          '        recomputed = "(could not recompute: " + type(e).__name__ + ")"',
          '        result["hash"] = False',
          "    if show:",
          '        show_value("hash received (sender)", rec["hash"])',
          '        show_value("hash recomputed (now)", recomputed)',
          '        show_value("hashes match", result["hash"])']
    if sig != "none" and user_keys:
        z += ["    try:",
              "        if show:",
              '            step("signature received (signed by " + rec["signer"] + ")", rec["sig"])',
              '            step("message it must cover (%s)", signed_part(rec))' % sig_msg,
              '        result["signature"] = verify_as(rec["signer"], rec["sig"], signed_part(rec), show)',
              "    except Exception:",
              '        result["signature"] = False',
              "    if show:",
              '        show_value("signed by", rec["signer"])',
              '        show_value("signature valid", result["signature"])']
        if cosign:
            z += ['    for entry in [e for e in rec["cosigs"].split(";") if e]:',
                  '        name, signature = entry.split(":", 1)',
                  "        try:",
                  '            ok = verify_as(name, signature, cosign_message(rec), show)',
                  "        except Exception:",
                  "            ok = False",
                  '        result["countersignature " + name] = ok',
                  "        if show:",
                  '            show_value("countersigned by " + name, ok)']
    elif sig != "none":
        z += ["    try:",
              "        if show:",
              '            step("signature received", rec["sig"])',
              '            step("message it must cover (%s)", signed_part(rec))' % sig_msg,
              '        result["signature"] = verify_sig(rec["sig"], signed_part(rec), show)',
              "    except Exception:",
              '        result["signature"] = False',
              "    if show:",
              '        show_value("signature valid", result["signature"])']
    if cfg["window"]:
        z += ['    result["period"] = K["start"] <= rec["time"][:16] <= K["end"]',
              "    if show:",
              '        show_value("timestamp", rec["time"])',
              '        show_value("allowed period", K["start"] + " .. " + K["end"])',
              '        show_value("inside the period", result["period"])']
    z += ["    return result", "", "", "def is_valid(rec):", "    return all(check_record(rec).values())"]
    prog.add("\n".join(z))

    # ---------------- indexes ----------------
    if index_fields:
        ix = ["# ---------- indexes: for search AND for filtering homomorphic calculations ----------",
              "#   plain : field=value | ID  stored in CLEAR (a normal index: the server can read it)"]
        if "sse" in types:
            ix.append("#   SSE   : HMAC-SHA256 token | AES-encrypted ID  (server sees neither value nor ID)")
        if "pkse" in types:
            ix.append("#   PKSE  : Paillier Enc(hash(word)) | Paillier Enc(ID)  (equality tested homomorphically)")
        ix += ["", "def index_record(rec_id, words, time_text):", "    plain_index_record(rec_id, words)"]
        if "sse" in types:
            ix.append("    sse_index_record(rec_id, words, time_text)")
        if "pkse" in types:
            ix.append("    pkse_index_record(rec_id, words)")
        parts = ["\n".join(ix), block(r'''
            def plain_index_record(rec_id, words):
                with open(PLAIN_INDEX_FILE, "a", encoding="utf-8") as f:
                    for word in words:
                        f.write(word + "|" + rec_id + "\n")
                        step("plain index entry", word + " -> " + rec_id)


            def plain_search_ids(word):
                found = set()
                if os.path.exists(PLAIN_INDEX_FILE):
                    with open(PLAIN_INDEX_FILE, "r", encoding="utf-8") as f:
                        for line in f:
                            stored_word, rec_id = line.rstrip("\n").rsplit("|", 1)
                            if stored_word == word:
                                found.add(rec_id)
                step("plain index: entries equal to '" + word + "'", sorted(found))
                return sorted(found)
        ''')]
        if "sse" in types:
            parts.append(block(r'''
                def sse_index_record(rec_id, words, time_text):
                    words = list(words) + ["hour=" + time_text[:13]]       # for time-range search
                    with open(SSE_INDEX_FILE, "a", encoding="utf-8") as f:
                        for word in words:
                            token = sse_trapdoor(K["sse"], word)
                            encrypted_id = aes_encrypt(K["sse"], rec_id)
                            f.write(token + "|" + encrypted_id + "\n")
                            step("SSE entry HMAC('" + word + "')", token + " -> AES(ID) " + encrypted_id)


                def sse_server_lookup(token):
                    """What the SERVER does: compare tokens, return encrypted IDs."""
                    found = []
                    if os.path.exists(SSE_INDEX_FILE):
                        with open(SSE_INDEX_FILE, "r", encoding="utf-8") as f:
                            for line in f:
                                stored_token, encrypted_id = line.rstrip("\n").split("|")
                                if stored_token == token:
                                    found.append(encrypted_id)
                    return found


                def sse_search_ids(word):
                    token = sse_trapdoor(K["sse"], word)                     # encrypt the query
                    step("query token = HMAC-SHA256(key, '" + word + "')", token)
                    encrypted_ids = sse_server_lookup(token)
                    step("encrypted IDs the server returned", encrypted_ids)
                    ids = sorted(set(aes_decrypt(K["sse"], e) for e in encrypted_ids))
                    step("IDs after AES decryption", ids)
                    return ids
            '''))
        if "pkse" in types:
            parts.append(block(r'''
                def pkse_index_record(rec_id, words):
                    with open(PKSE_INDEX_FILE, "a", encoding="utf-8") as f:
                        for word in words:
                            encrypted_word = paillier_encrypt(K["p_n"], K["p_g"], _word_number(word))
                            encrypted_id = paillier_encrypt(K["p_n"], K["p_g"], _text_to_number(rec_id))
                            f.write(str(encrypted_word) + "|" + str(encrypted_id) + "\n")
                            step("PKSE entry Enc(hash('" + word + "'))", encrypted_word)


                def pkse_search_ids(word):
                    n = K["p_n"]
                    query = paillier_encrypt(n, K["p_g"], _word_number(word))
                    step("Enc(hash('" + word + "')) sent to the server", query)
                    found = set()
                    if os.path.exists(PKSE_INDEX_FILE):
                        with open(PKSE_INDEX_FILE, "r", encoding="utf-8") as f:
                            for number, line in enumerate(f, start=1):
                                encrypted_word, encrypted_id = map(int, line.rstrip("\n").split("|"))
                                difference = paillier_subtract(n, encrypted_word, query)                  # server
                                blinded = paillier_multiply_plain(n, difference, getRandomRange(1, 2 ** 64))
                                if paillier_decrypt(n, K["p_lam"], K["p_mu"], blinded) == 0:             # key holder
                                    rec_id = _number_to_text(paillier_decrypt(n, K["p_lam"], K["p_mu"], encrypted_id))
                                    step("entry " + str(number), "Enc((word - query) * r) decrypts to 0 -> MATCH, ID " + rec_id)
                                    found.add(rec_id)
                                else:
                                    step("entry " + str(number), "decrypts to non-zero -> no match")
                    return sorted(found)
            '''))
        query = [block(r'''
            def ask_index_query():
                """Asks which index, which field and which value; returns the matching IDs."""
                print("Index: plain = normal index stored in clear{{more}}")
                method = SEARCH_METHODS[0] if len(SEARCH_METHODS) == 1 else ask_choice("Search with", SEARCH_METHODS)
                fields = [ID_LABEL] + INDEX_FIELDS if method == "plain" else INDEX_FIELDS
                field = fields[0] if len(fields) == 1 else ask_choice("Search by", fields)
                value = ask_text(field + " = ")
                return index_lookup(method, field, value)


            def index_lookup(method, field, value):
                """IDs whose field equals value, looked up in the plain / SSE / PKSE index."""
                if field == ID_LABEL:
                    return [value] if find_record(value) is not None else []
                word = field.lower() + "=" + value.lower()
                if method == "plain":
                    return plain_search_ids(word)
        ''').replace("{{more}}", ("; SSE = HMAC tokens + AES" if "sse" in types else "")
                     + ("; PKSE = Paillier, public key" if "pkse" in types else ""))]
        if "sse" in types:
            query.append('    if method == "SSE":\n        return sse_search_ids(word)')
        if "pkse" in types:
            query.append('    if method == "PKSE":\n        return pkse_search_ids(word)')
        query.append("    return []")
        parts.append("\n".join(query))
        if "search_time" in cfg["used"] and "sse" in types:
            parts.append(block(r'''
                def hours_between(start, end):
                    """Every 'YYYY-MM-DD HH' bucket from start to end (both 'YYYY-MM-DD HH:MM')."""
                    hour = datetime.strptime(start[:13], "%Y-%m-%d %H")
                    last = datetime.strptime(end[:13], "%Y-%m-%d %H")
                    buckets = []
                    while hour <= last:
                        buckets.append(hour.strftime("%Y-%m-%d %H"))
                        hour += timedelta(hours=1)
                    return buckets
            '''))
        prog.add("\n\n\n".join(parts))

    # ---------------- plumbing ----------------
    prog.add(block(r'''
        # ---------- plumbing: storage (one record per line, fields joined with "|") ----------

        def load_records():
            records = []
            if not os.path.exists(RECORDS_FILE):
                return records
            with open(RECORDS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.rstrip("\n").split("|")
                    if len(parts) == len(FIELDS):
                        records.append(dict(zip(FIELDS, parts)))
                    elif line.strip():
                        print("Skipping damaged line in", RECORDS_FILE)
            return records


        def save_records(records):
            with open(RECORDS_FILE, "w", encoding="utf-8") as f:
                for rec in records:
                    f.write("|".join(rec[name] for name in FIELDS) + "\n")


        def append_record(rec):
            with open(RECORDS_FILE, "a", encoding="utf-8") as f:
                f.write("|".join(rec[name] for name in FIELDS) + "\n")


        def find_record(rec_id):
            """The record with this ID, or None. IDs are compared as strings."""
            for rec in load_records():
                if rec["id"] == rec_id:
                    return rec
            return None


        {{LOG}}
    ''').replace("{{LOG}}", block(r'''
        def log_access(action, rec_id, status):
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(timestamp() + "|" + ROLE + "|" + action + "|" + rec_id + "|" + status + "\n")
    ''') if cfg["access_log"] else block(r'''
        def log_access(action, rec_id, status):
            """No access log in this question -- kept so every action can still call it."""
            return
    ''')) + ("\n\n\n" + block(r'''
        def save_decrypted(rec_id, plaintext):
            """History: one line per successful decryption -- time|role|ID|plaintext (newlines as ' / ')."""
            with open(DECRYPTED_FILE, "a", encoding="utf-8") as f:
                f.write(timestamp() + "|" + ROLE + "|" + rec_id + "|" + plaintext.strip().replace("\n", " / ") + "\n")
            print("  (appended to " + DECRYPTED_FILE + ")")
    ''') if cfg["decrypted_file"] and "decrypt" in cfg["used"] else ""))

    helpers = [block(r'''
        # ---------- plumbing: input + output helpers ----------

        def ask_text(prompt):
            while True:
                s = input(prompt).strip()
                if s and "|" not in s:
                    return s
                print("Must be non-empty and must not contain '|'.")
    ''')]
    if cfg["rules"]:
        prog.need("import re")
        helpers.append(block(r'''
            FIELD_PATTERNS = {{patterns}}


            def rule_problem(field, value):
                """None if value obeys CONSTRAINTS[field], otherwise the reason."""
                rule = CONSTRAINTS[field]
                if isinstance(value, int):
                    if "min" in rule and value < rule["min"]:
                        return "must be at least " + str(rule["min"])
                    if "max" in rule and value > rule["max"]:
                        return "must be at most " + str(rule["max"])
                    return None
                if "min_len" in rule and len(value) < rule["min_len"]:
                    return "must have at least " + str(rule["min_len"]) + " characters"
                if "max_len" in rule and len(value) > rule["max_len"]:
                    return "must have at most " + str(rule["max_len"]) + " characters"
                if "allowed" in rule and value.lower() not in [a.lower() for a in rule["allowed"]]:
                    return "must be one of: " + ", ".join(rule["allowed"])
                if "pattern" in rule:
                    regex, meaning = FIELD_PATTERNS.get(rule["pattern"], (rule["pattern"], "in the format " + rule["pattern"]))
                    if not re.fullmatch(regex, value):
                        return "must be " + meaning
                    if rule["pattern"] == "date":
                        try:
                            datetime.strptime(value, "%Y-%m-%d")
                        except ValueError:
                            return "is not a real date"
                return None


            def ask_checked(prompt, field, as_int=False):
                """Asks again until the value obeys the field's constraints."""
                while True:
                    if as_int:
                        text = input(prompt).strip()
                        try:
                            value = int(text)
                        except ValueError:
                            print("  INVALID " + field + ": must be a whole number")
                            continue
                    else:
                        value = ask_text(prompt)
                    problem = rule_problem(field, value)
                    if problem is None:
                        return value
                    print("  INVALID " + field + ": " + problem)
        ''').replace("{{patterns}}", json.dumps(FIELD_PATTERNS).replace("], ", "],\n                  ")))
    if any(f["kind"] == "int" for f in fields):
        helpers.append(block(r'''
            def ask_int(prompt, minimum=0):
                while True:
                    s = input(prompt).strip()
                    try:
                        value = int(s)
                        if value >= minimum:
                            return value
                    except ValueError:
                        pass
                    print("Enter a whole number >=", minimum)
        '''))
    helpers.append(block(r'''
        def ask_choice(prompt, options):
            while True:
                print(prompt + ": " + ", ".join(str(i) + "=" + o for i, o in enumerate(options, start=1)))
                s = input("> ").strip()
                if s.isdigit() and 1 <= int(s) <= len(options):
                    return options[int(s) - 1]
                for option in options:
                    if s.lower() == option.lower():
                        return option
                print("Pick one of the listed options.")
    '''))
    if any(f["kind"] == "file" for f in fields):
        helpers.append(block(r'''
            def ask_file(prompt):
                """Reads a whole .txt file. A relative name is also tried next to this script."""
                while True:
                    path = input(prompt).strip()
                    for candidate in (path, os.path.join(HERE, path)):
                        if os.path.isfile(candidate):
                            with open(candidate, "r", encoding="utf-8") as f:
                                return f.read()
                    print("Cannot find", path)
        '''))
    if cfg["window"] or cfg["decrypt_window"] or "search_time" in cfg["used"]:
        helpers.append(block(r'''
            def ask_time(prompt, default=None):
                while True:
                    s = input(prompt).strip()
                    if not s and default is not None:
                        return default
                    try:
                        return datetime.strptime(s, "%Y-%m-%d %H:%M").strftime("%Y-%m-%d %H:%M")
                    except ValueError:
                        print("Use the format YYYY-MM-DD HH:MM, e.g. 2026-11-20 09:30")
        '''))
    helpers.append(block(r'''
        def short(s, n=40):
            return s if len(s) <= n else s[:n] + "..."


        def label(ok):
            return "OK" if ok else "FAILED"


        def status_of(result):
            return "VALID" if all(result.values()) else "INVALID"


        def checks_text(result):
            return " | ".join(name + " " + label(ok) for name, ok in result.items())


        def show_full(rec, full=None):
            """Every stored field; full=True prints the values untruncated."""
            if full is None:
                full = SHOW_STEPS
            width = max(len(name) for name in FIELDS + ["status"])
            for name in FIELDS:
                print("  " + name.ljust(width) + " : " + (wrap_value(rec[name], width + 5) if full else short(rec[name], 60)))


        def show_results(ids):
            """Search result: the COMPLETE encrypted record of every match."""
            section("search result")
            show_value("matching IDs", ", ".join(ids) if ids else "none")
            for rec_id in ids:
                rec = find_record(rec_id)
                section("record " + rec_id)
                show_full(rec, full=True)
                result = check_record(rec)
                width = max(len(name) for name in FIELDS + ["status"])
                print("  " + "status".ljust(width) + " : " + checks_text(result) + " -> " + status_of(result))


        def safe(fn):
            """Wrap a menu action: an exception prints instead of crashing the menu."""
            def run():
                try:
                    fn()
                except Exception as e:
                    print("Error:", type(e).__name__, e)
            return run


        def run_menu(title, options, back_label="Back"):
            # from system_parts/role_menu.py
            while True:
                print("\n--- " + title + " ---")
                for number, (text, _) in enumerate(options, start=1):
                    print(str(number) + ". " + text)
                print(str(len(options) + 1) + ". " + back_label)

                choice = input("Choice: ").strip()

                if choice == str(len(options) + 1):
                    return
                if choice.isdigit() and 1 <= int(choice) <= len(options):
                    safe(options[int(choice) - 1][1])()
                else:
                    print("Invalid choice.")
    '''))
    prog.add("\n\n\n".join(helpers))

    # ---------------- actions ----------------
    noun, Noun = cfg["noun"], cfg["noun"][0].upper() + cfg["noun"][1:]
    acts = ["# ==================== EDIT ZONE 3: menu actions ===================="]

    a = ["def add_record():",
         ("    rec_id = ask_checked(%s, ID_LABEL)" % q(cfg["id_label"] + ": ") if cfg["id_label"] in cfg["rules"]
          else "    rec_id = ask_text(%s)" % q(cfg["id_label"] + ": ")),
         "    if find_record(rec_id) is not None:",
         "        print(%s, rec_id, \"already exists -- not stored again.\")" % q(cfg["id_label"]),
         "        return"]
    for f in fields:
        if f["kind"] == "text":
            if f["label"] in cfg["rules"]:
                a.append("    %s = ask_checked(%s, %s)" % (f["var"], q(f["label"] + ": "), q(f["label"])))
            else:
                a.append("    %s = ask_text(%s)" % (f["var"], q(f["label"] + ": ")))
        elif f["kind"] == "int":
            if f["label"] in cfg["rules"]:
                a.append("    %s = ask_checked(%s, %s, as_int=True)" % (f["var"], q(f["label"] + ": "), q(f["label"])))
            else:
                a.append("    %s = ask_int(%s)" % (f["var"], q(f["label"] + ": ")))
        elif f["kind"] == "choice":
            a.append("    %s = ask_choice(%s, CHOICES)" % (f["var"], q(f["label"])))
        else:
            a.append("    %s = ask_file(%s)" % (f["var"], q("File with the " + f["label"].lower() + ": ")))
    if fenc and not main_fields:
        a.append('    plaintext = "(every field is encrypted separately)"')
    elif fenc:
        a.append("    plaintext = " + ' + "\\n" + '.join("%s + %s" % (q(f["label"] + ": "), as_text(f)) for f in main_fields))
    elif len(fields) == 1 and fields[0]["kind"] == "file":
        a.append("    plaintext = " + fields[0]["var"])
    else:
        a.append("    plaintext = " + ' + "\\n" + '.join("%s + %s" % (q(f["label"] + ": "), as_text(f)) for f in fields))
    if cfg["extra"]:
        a.append("    extra = ask_text(%s)" % q(cfg["extra"]["label"] + ": "))
    a += ["", '    section("encrypting " + rec_id)', '    step("plaintext", plaintext)',
          '    rec = {"id": rec_id}', "    rec.update(encrypt_data(plaintext))"]
    for f in fenc:
        a.append('    rec["f_%s"] = encrypt_field_%s(%s)' % (f["var"], f["var"], as_text(field_by_label(cfg, f["label"]))))
    if fenc and cfg["hash_over"] == "plaintext":
        parts = ["plaintext"]
        parts += ["%s + %s" % (q(f["label"] + ": "), as_text(field_by_label(cfg, f["label"]))) for f in fenc]
        a.append("    full_plaintext = " + ' + "\\n" + '.join(parts))
    if cfg["extra"]:
        a.append('    rec["extra"] = encrypt_extra(extra)')
    done = set()
    for op in ops:
        if op["store"] in done:
            continue
        done.add(op["store"])
        if op["type"] == "votes":
            a += ['    rec["votes"] = encrypt_vote(%s)' % op["var"],
                  '    step("Paillier one-hot ballot (Enc per option, ; separated)", rec["votes"])']
        elif op["scheme"] == "m":
            a += ['    rec["%s"] = he_encrypt_mul(%s)' % (op["store"], op["var"]),
                  '    step("textbook RSA Enc(%s) = %s^e mod n", rec["%s"])' % (op["label"], op["label"].lower(), op["store"])]
        elif op["scheme"] == "e":
            a += ['    rec["%s"] = he_encrypt_eg(%s)' % (op["store"], op["var"]),
                  '    step("ElGamal Enc(%s) = (g^k, m*h^k) mod p", rec["%s"])' % (op["label"], op["store"])]
        elif op["scheme"] == "x":
            a += ['    rec["%s"] = he_encrypt_egx(%s)' % (op["store"], op["var"]),
                  '    step("exponential ElGamal Enc(g^%s) = (g^k, g^m*h^k) mod p", rec["%s"])' % (op["label"], op["store"])]
        else:
            a += ['    rec["%s"] = he_encrypt_add(%s)' % (op["store"], op["var"]),
                  '    step("Paillier Enc(%s) = g^m * r^n mod n^2", rec["%s"])' % (op["label"], op["store"])]
    a += ['    rec["time"] = timestamp()', '    step("timestamp", rec["time"])']
    if user_keys:
        a += ['    rec["signer"] = current_signer()', '    step("signer", rec["signer"])']
    hname = HASHES[cfg["hash"]]
    if cfg["hash_over"] == "plaintext" and fenc:
        a += ['    step("data hashed (the plaintext)", full_plaintext)', '    rec["hash"] = hash_fn(full_plaintext)']
    elif cfg["hash_over"] == "plaintext":
        a += ['    step("data hashed (the plaintext)", plaintext)', '    rec["hash"] = hash_fn(plaintext)']
    else:
        a += ['    step("data hashed (id|ciphertexts|time)", hashed_part(rec))', '    rec["hash"] = hash_fn(hashed_part(rec))']
    a.append('    step("%s hash", rec["hash"])' % hname)
    if sig != "none" and user_keys:
        a += ['    step("message signed (%s)", signed_part(rec))' % sig_msg,
              '    rec["sig"] = sign_as(rec["signer"], signed_part(rec))',
              '    step("%s by " + rec["signer"] + " (their own key)", rec["sig"])' % SIGNATURES[sig]]
        if cosign:
            a.append('    rec["cosigs"] = ""                  # countersignatures are added later')
    elif sig != "none":
        a += ['    step("message signed (%s)", signed_part(rec))' % sig_msg,
              '    rec["sig"] = sign(signed_part(rec))',
              '    step("%s", rec["sig"])' % SIGNATURES[sig]]
    a.append("    append_record(rec)")
    if index_fields:
        words = []
        for label_ in index_fields:
            f = field_by_label(cfg, label_)
            words.append("%s + %s.lower()" % (q(f["label"].lower() + "="), as_text(f)))
        a.append('    index_record(rec_id, [%s], rec["time"])' % ", ".join(words))
    if cfg["window"]:
        a += ['    if not K["start"] <= rec["time"][:16] <= K["end"]:',
              '        print("WARNING: outside the %s -- this %s will fail verification.")' % (cfg["window"], noun)]
    a += ['    section("%s stored")' % Noun, "    show_full(rec)", '    print("  (saved in " + RECORDS_FILE + ")")']
    acts.append("\n".join(a))

    if "view" in cfg["used"]:
        acts.append(block(r'''
            def view_all():
                records = load_records()
                if not records:
                    print("No records yet.")
                for rec in records:
                    section(ID_LABEL + " " + rec["id"])
                    show_full(rec)
        '''))
    if "view_meta" in cfg["used"]:
        acts.append(block(r'''
            def view_meta():
                """ID, timestamp and hash only -- no ciphertext, no decryption."""
                records = load_records()
                if not records:
                    print("No records yet.")
                for rec in records:
                    section(ID_LABEL + " " + rec["id"])
                    show_value("timestamp", rec["time"], 10)
                    show_value("hash", rec["hash"], 10)
                    show_value("status", status_of(check_record(rec)), 10)
        '''))
    if "verify" in cfg["used"]:
        acts.append(block(r'''
            def verify_all():
                records = load_records()
                if not records:
                    print("No records yet.")
                for rec in records:
                    section("verifying " + rec["id"])
                    result = check_record(rec, show=True)
                    show_value("RESULT", checks_text(result) + "  ->  " + status_of(result))
                    log_access("verify", rec["id"], status_of(result))
        '''))
    if "verify_one" in cfg["used"]:
        acts.append(block(r'''
            def verify_one():
                """Hash + signature (+ time) of ONE record. The record's contents are never shown."""
                rec = find_record(ask_text(ID_LABEL + " to verify: "))
                if rec is None:
                    print("Not found.")
                    return None
                section("verifying " + rec["id"] + " (contents not shown)")
                result = check_record(rec, show=True)
                show_value("RESULT", checks_text(result) + "  ->  " + status_of(result))
                log_access("verify", rec["id"], status_of(result))
                return all(result.values())
        '''))
    if "decrypt" in cfg["used"]:
        d = ["def decrypt_one():",
             "    rec = find_record(ask_text(%s))" % q(cfg["id_label"] + " to decrypt: "),
             "    if rec is None:",
             '        print("Not found.")',
             "        return None",
             '    section("verifying " + rec["id"] + " first")',
             "    result = check_record(rec, show=True)",
             '    show_value("RESULT", checks_text(result) + "  ->  " + status_of(result))',
             "    if not all(result.values()):",
             '        print("Verification FAILED -- refusing to decrypt.")',
             '        log_access("decrypt", rec["id"], "DENIED")',
             "        return None"]
        if dwin:
            d += ['    now = datetime.now().strftime("%Y-%m-%d %H:%M")',
                  '    show_value("decryption allowed", K["dstart"] + " .. " + K["dend"])',
                  '    show_value("time now", now)',
                  '    if not K["dstart"] <= now <= K["dend"]:',
                  '        print("Outside the %s -- decryption refused.")' % dwin,
                  '        log_access("decrypt", rec["id"], "DENIED (outside %s)")' % dwin,
                  "        return None"]
        d += ['    section("decrypting " + rec["id"])',
             "    try:",
             "        plaintext = %s(rec, show=True)" % ("decrypt_all" if fenc else "decrypt_data"),
             "    except Exception as e:",
             '        print("Decryption failed (wrong key?):", type(e).__name__, e)',
             '        log_access("decrypt", rec["id"], "FAILED")',
             "        return None",
             '    section("decrypted %s")' % noun,
             '    for line in plaintext.split("\\n"):',
             '        print("    " + line)']
        if cfg["extra"]:
            d += ['    extra_text = decrypt_extra(rec["extra"])',
                  '    show_value("%s", extra_text)' % cfg["extra"]["label"]]
        if cfg["decrypted_file"]:
            d.append('    save_decrypted(rec["id"], plaintext%s)'
                     % ('.strip() + "\\n%s: " + extra_text' % cfg["extra"]["label"] if cfg["extra"] else ""))
        d += ['    log_access("decrypt", rec["id"], "GRANTED")', "    return plaintext"]
        acts.append("\n".join(d))
    if "report" in cfg["used"]:
        acts.append(block(r'''
            def compliance_report():
                """Checks every record WITHOUT decrypting anything, writes REPORT_FILE."""
                records = load_records()
                lines = ["COMPLIANCE REPORT  " + timestamp(), "records checked: " + str(len(records)), ""]
                valid = 0
                for rec in records:
                    result = check_record(rec)
                    valid += all(result.values())
                    lines.append(rec["id"] + " | " + rec["time"] + " | " + checks_text(result) + " | " + status_of(result))
                lines += ["", "valid: " + str(valid) + "   invalid: " + str(len(records) - valid)]
                with open(REPORT_FILE, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
                print("\n".join(lines))
                print("Report written to", REPORT_FILE)
                log_access("report", "-", "valid " + str(valid) + "/" + str(len(records)))
                return valid
        '''))

    if ops:
        modes = set(op["select"] for op in ops)
        sel = [block(r'''
            # ---------- which records a homomorphic operation uses ----------

            def records_for(ids):
                records = []
                for rec_id in ids:
                    rec = find_record(rec_id)
                    if rec is None:
                        print("  ", rec_id, ": not found, skipped")
                    else:
                        records.append(rec)
                print("Selected:", [rec["id"] for rec in records])
                return records


            def select_all():
                records = load_records()
                print("Selected: all", len(records), "records")
                return records


            def select_by_ids():
                return records_for([x.strip() for x in ask_text("IDs, comma separated: ").split(",") if x.strip()])
        ''')]
        if index_fields:
            sel.append(block(r'''
                def select_by_filter(method, field):
                    value = ask_text(field + " = ")
                    print("Filter", field, "=", value, "through the", method, "index")
                    return records_for(index_lookup(method, field, value))
            '''))
        if "ask" in modes:
            filter_lines = ""
            if index_fields:
                filter_lines = '\n    print("3. Filter by a field value (uses the plain / encrypted index)")'
            sel.append(block(r'''
                def choose_records(purpose):
                    """Run-time menu: all records, a list of IDs, or a filter through an index."""
                    print("Which records go into the " + purpose + "?")
                    print("1. All records")
                    print("2. Specific IDs"){{filter}}
                    choice = input("> ").strip()
                    if choice == "2":
                        return select_by_ids()
                    {{elif}}return select_all()
            ''').replace("{{filter}}", filter_lines).replace(
                "{{elif}}", 'if choice == "3":\n        return records_for(ask_index_query())\n    ' if index_fields else ""))
        acts.append("\n\n\n".join(sel))

    for op in ops:
        acts.append(he_function(op))

    if "search" in cfg["used"]:
        acts.append(block(r'''
            def search_records():
                """Plain or encrypted index lookup; prints the COMPLETE stored record of every match."""
                ids = ask_index_query()
                show_results(ids)
                log_access("search", ",".join(ids) or "-", str(len(ids)) + " match(es)")
                return ids
        '''))
    if "search_time" in cfg["used"]:
        t = ["def search_time_range():",
             "    method = TIME_METHODS[0] if len(TIME_METHODS) == 1 else ask_choice(\"Search with\", TIME_METHODS)",
             '    start = ask_time("From (YYYY-MM-DD HH:MM): ")',
             '    end = ask_time("To   (YYYY-MM-DD HH:MM): ")']
        if "sse" in types:
            t += ['    if method == "SSE":',
                  "        ids = set()",
                  "        for hour in hours_between(start, end):        # the encrypted index works per hour ...",
                  '            ids.update(sse_search_ids("hour=" + hour))',
                  "        candidates = [find_record(i) for i in sorted(ids)]",
                  "    else:",
                  "        candidates = load_records()                   # plain: read the stored timestamps"]
        else:
            t.append("    candidates = load_records()                       # plain: read the stored timestamps")
        t += ['    found = [rec["id"] for rec in candidates if start <= rec["time"][:16] <= end]   # exact minutes',
              "    show_results(found)",
              '    log_access("search", ",".join(found) or "-", start + " .. " + end)',
              "    return found"]
        acts.append("\n".join(t))
    if "cosign" in cfg["used"]:
        acts.append(block(r'''
            def cosign_record():
                """A second user signs (signed message|first signature) with THEIR OWN key."""
                rec_id = ask_text(ID_LABEL + " to countersign: ")
                records = load_records()
                rec = next((r for r in records if r["id"] == rec_id), None)
                if rec is None:
                    print("Not found.")
                    return None
                section("verifying " + rec_id + " before countersigning")
                result = check_record(rec, show=True)
                if not all(result.values()):
                    print("Verification FAILED -- refusing to countersign.")
                    return None
                name = current_signer()
                already = [rec["signer"]] + [e.split(":", 1)[0] for e in rec["cosigs"].split(";") if e]
                if name in already:
                    print(name, "has already signed this record.")
                    return None
                message = cosign_message(rec)
                step("message countersigned = hash of (signed message|first signature)", message)
                signature = sign_as(name, message)
                step("countersignature by " + name, signature)
                rec["cosigs"] = (rec["cosigs"] + ";" if rec["cosigs"] else "") + name + ":" + signature
                save_records(records)
                result_line(rec_id + " countersigned by " + name)
                log_access("cosign", rec_id, name)
                return True
        '''))
    if "show_keys" in cfg["used"]:
        acts.append(block(r'''
            def show_keys():
                load_user_keys()
                if not USER_KEYS:
                    print("No signer has a key pair yet.")
                for name, keys in USER_KEYS.items():
                    section("public key of " + name)
                    for number in public_part(keys):
                        print("    " + wrap_value(number, 4))
        '''))
    if login:
        acts.append(block(r'''
            def hash_password(password, salt):
                """Salted PBKDF2 -- only this is stored, never the password."""
                return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()


            def load_users():
                users = {}
                if os.path.exists(USERS_FILE):
                    with open(USERS_FILE, "r", encoding="utf-8") as f:
                        for line in f:
                            role, name, salt, stored = line.rstrip("\n").split("|")
                            users[(role, name)] = (bytes.fromhex(salt), stored)
                return users


            def login(role):
                """Returns the user name, or None. An unknown user may register (sets a password)."""
                section(role + " login")
                users = load_users()
                name = ask_text("Username: ")
                if (role, name) not in users:
                    if ask_text("No " + role + " user called " + name + ". Register now? (y/n): ").lower() != "y":
                        return None
                    password = ask_text("Choose a password: ")
                    salt = os.urandom(16)
                    stored = hash_password(password, salt)
                    step("salt", salt.hex())
                    step("PBKDF2(password, salt) -- stored instead of the password", stored)
                    with open(USERS_FILE, "a", encoding="utf-8") as f:
                        f.write(role + "|" + name + "|" + salt.hex() + "|" + stored + "\n")
                    print("Registered", name, "as", role)
                    log_access("register", name, role)
                    return name
                salt, stored = users[(role, name)]
                for attempt in range(3):
                    computed = hash_password(ask_text("Password: "), salt)
                    step("PBKDF2 of the typed password", computed)
                    if hmac.compare_digest(computed, stored):
                        print("Login OK:", name, "as", role)
                        log_access("login", name, "OK")
                        return name
                    print("Wrong password.")
                print("Too many wrong passwords.")
                log_access("login", name, "FAILED")
                return None
        '''))
    if sockets:
        decrypt_call = ("decrypt_all" if fenc else "decrypt_data") \
            if cfg["key_src"] not in ("typed_each", "password") else None
        if decrypt_call:
            server_decrypt = ("\n    plaintext = %s(rec, show=True)"
                              "\n    section(\"decrypted on the server\")"
                              "\n    for line in plaintext.split(\"\\n\"):"
                              "\n        print(\"    \" + line)") % decrypt_call
        else:
            server_decrypt = "\n    print(\"(the key is typed by the user, so the server only verifies and stores)\")"
        acts.append(block(r'''
            # ---------- socket mode:  python THIS_FILE server   /   python THIS_FILE client ----------

            def receive_line(conn):
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                return data.decode().rstrip("\n")


            def handle_incoming(line):
                """Server side: verify a received record, store it only if every check passes."""
                section("record received")
                parts = line.split("|")
                if len(parts) != len(FIELDS):
                    return "REJECTED: malformed record"
                rec = dict(zip(FIELDS, parts))
                result = check_record(rec, show=True)
                show_value("RESULT", checks_text(result) + "  ->  " + status_of(result))
                if not all(result.values()):
                    log_access("receive", rec["id"], "REJECTED")
                    return "REJECTED (tampered / not authentic): " + checks_text(result)
                if find_record(rec["id"]) is not None:
                    return "REJECTED: duplicate ID " + rec["id"]
                append_record(rec){{decrypt}}
                log_access("receive", rec["id"], "ACCEPTED")
                return "ACK: " + rec["id"] + " verified and stored"


            def server_loop(max_connections=None, ready=None):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server.bind((HOST, PORT))
                    server.listen()
                    print("Server listening on", HOST, PORT, "(Ctrl+C to stop)")
                    if ready is not None:
                        ready.set()
                    handled = 0
                    while max_connections is None or handled < max_connections:
                        conn, address = server.accept()
                        with conn:
                            reply = handle_incoming(receive_line(conn))
                            conn.sendall((reply + "\n").encode())
                        show_value("replied", reply)
                        handled += 1


            def send_record(rec):
                """Client side: one record per connection, one reply line back."""
                line = "|".join(rec[name] for name in FIELDS)
                step("sending", line)
                with socket.create_connection((HOST, PORT)) as client:
                    client.sendall((line + "\n").encode())
                    reply = receive_line(client)
                show_value("server replied", reply)
                return reply


            def client_send_new():
                before = len(load_records())
                add_record()
                records = load_records()
                if len(records) > before:
                    return send_record(records[-1])
                return None


            def client_send_tampered():
                records = load_records()
                if not records:
                    print("Create and send a record first.")
                    return None
                rec = dict(records[-1])
                rec["enc"] = rec["enc"][:-1] + ("0" if rec["enc"][-1] != "0" else "1")
                print("Sending a copy of", rec["id"], "with one ciphertext character changed.")
                return send_record(rec)


            def server_main():
                global ROLE
                ROLE = "server"
                setup_keys()
                server_loop()


            def client_main():
                global ROLE
                # the client keeps its OWN copy of every data file (same folder as the server)
                for name in [n for n in globals() if n.endswith("_FILE") and n not in ("KEYS_FILE", "WRAPPED_KEY_FILE",
                                                                                         "USERS_FILE", "SIGNER_KEYS_FILE")]:
                    globals()[name] = globals()[name].replace(".txt", "_client.txt")
                ROLE = "client"
                setup_keys(){{login}}
                run_menu("CLIENT -> server " + HOST + ":" + str(PORT), [
                    ("Create a new record and send it", client_send_new),
                    ("Send a TAMPERED copy of the last record", client_send_tampered),
                ], back_label="Exit")
        ''').replace("{{decrypt}}", server_decrypt).replace("{{login}}", """
    global CURRENT_USER
    user = None
    while user is None:
        user = login("Client")
    CURRENT_USER = user""" if login else ""))
    if cfg["file_input"]:
        prog.need("import builtins")
        acts.append(block(r'''
            # ---------- inputs from a .txt file ----------

            def feed(fn, answers):
                """Runs fn() with every input() answered from the list -- no keyboard.
                Returns False if a value is rejected (the same question asked twice) or missing."""
                queue = list(answers)
                last = [None]
                real_input = builtins.input

                def scripted(prompt=""):
                    if prompt == last[0]:
                        raise ValueError("value rejected for " + prompt.strip(" :>"))
                    if not queue:
                        raise ValueError("not enough values")
                    last[0] = prompt
                    answer = queue.pop(0)
                    print(prompt + answer)
                    return answer

                builtins.input = scripted
                try:
                    fn()
                    return True
                except ValueError as e:
                    print("  REJECTED:", e)
                    return False
                finally:
                    builtins.input = real_input


            def import_records(path=None):
                """Adds every record of a .txt file (one per line, IMPORT_COLUMNS order) without typing."""
                print("Each line: " + (" " + IMPORT_SEPARATOR + " ").join(IMPORT_COLUMNS))
                path = path or ask_text("Import file (.txt): ")
                if not os.path.isfile(path) and os.path.isfile(os.path.join(HERE, path)):
                    path = os.path.join(HERE, path)
                if not os.path.isfile(path):
                    print("Cannot find", path)
                    return []
                added = []
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
                for number, line in enumerate(lines, start=1):
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    values = [v.strip() for v in line.split(IMPORT_SEPARATOR)]
                    section("import line " + str(number))
                    if len(values) != len(IMPORT_COLUMNS):
                        print("  SKIPPED: expected", len(IMPORT_COLUMNS), "values, found", len(values))
                        continue
                    before = len(load_records())
                    if feed(add_record, values) and len(load_records()) > before:
                        added.append(values[0])
                    elif len(load_records()) == before:
                        print("  SKIPPED line", number)
                result_line("imported " + str(len(added)) + " record(s): " + (", ".join(added) or "none"))
                log_access("import", ",".join(added) or "-", os.path.basename(path))
                return added


            def run_from_file(path):
                """python THIS_FILE --answers answers.txt : each question takes the next line of the file."""
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
                real_input = builtins.input

                def scripted(prompt=""):
                    if lines:
                        answer = lines.pop(0)
                        print(prompt + answer)
                        return answer
                    return real_input(prompt)            # file used up -> keyboard

                builtins.input = scripted
                main()
        '''))
    acts.append(block(r'''
        def tamper_record():
            """Demo only: change one character of a stored ciphertext."""
            rec_id = ask_text("ID to tamper with: ")
            records = load_records()
            for rec in records:
                if rec["id"] == rec_id:
                    c = rec["enc"]
                    rec["enc"] = c[:-1] + ("0" if c[-1] != "0" else "1")
                    save_records(records)
                    print("Changed the last character of the stored ciphertext of", rec_id)
                    return
            print("Not found.")
    '''))
    prog.add("\n\n\n".join(acts))

    # ---------------- main ----------------
    labels = action_labels(cfg)
    fn = {"add": "add_record", "view": "view_all", "view_meta": "view_meta", "verify": "verify_all",
          "decrypt": "decrypt_one", "report": "compliance_report", "verify_one": "verify_one",
          "search": "search_records", "search_time": "search_time_range",
          "cosign": "cosign_record", "show_keys": "show_keys", "import": "import_records"}
    for op in ops:
        fn[op["action"]] = op["action"]
    data_files = ["RECORDS_FILE", "LOG_FILE"] + index_files
    if cfg["decrypted_file"] and "decrypt" in cfg["used"]:
        data_files.append("DECRYPTED_FILE")
    m = ["def clear_files():",
         '    """Fresh keys -> old records can never verify again, so start with empty files."""',
         "    for path in (%s):" % ", ".join(data_files),
         "        if os.path.exists(path):",
         "            os.remove(path)", "", "",
         "def main():", "    global ROLE" + (", CURRENT_USER" if login else ""), "    setup_keys()"]
    if not persist:
        m.append("    clear_files()")
    if cfg["roles"][0][0] is None:
        m.append('    ROLE = "user"')
        if login:
            m += ["    user = None", "    while user is None:", '        user = login("user")',
                  "    CURRENT_USER = user", '    ROLE = "user (" + user + ")"']
        m.append("    run_menu(%s, [" % q(cfg["name"].upper()))
        for a_ in cfg["roles"][0][1]:
            m.append("        (%s, %s)," % (q(labels[a_]), fn[a_]))
        m.append('        ("(demo) Tamper with a stored %s", tamper_record),' % noun)
        m.append('    ], back_label="Exit")')
    else:
        roles = cfg["roles"]
        r = len(roles)
        m += ["    while True:", '        print("\\n===== %s =====")' % cfg["name"].upper()]
        for i, (role, _) in enumerate(roles, start=1):
            m.append('        print("%d. %s")' % (i, role))
        m.append('        print("%d. (demo) Tamper with a stored %s")' % (r + 1, noun))
        m.append('        print("%d. Exit")' % (r + 2))
        m.append('        choice = input("Role: ").strip()')
        m.append("")
        for i, (role, actions) in enumerate(roles, start=1):
            m.append('        %s choice == "%d":' % ("if" if i == 1 else "elif", i))
            m.append("            ROLE = %s" % q(role))
            if login:
                m += ["            user = login(%s)" % q(role), "            if user is None:", "                continue",
                      "            CURRENT_USER = user", '            ROLE = %s + " (" + user + ")"' % q(role)]
            m.append("            run_menu(%s, [" % q(role))
            for a_ in actions:
                m.append("                (%s, %s)," % (q(labels[a_]), fn[a_]))
            m.append("            ])")
        m += ['        elif choice == "%d":' % (r + 1), "            safe(tamper_record)()",
              '        elif choice == "%d":' % (r + 2), '            print("Bye.")', "            break",
              "        else:", '            print("Invalid choice.")']
    prog.add("\n".join(m))

    prog.add(build_records_test(cfg), "import os")
    if sockets:
        prog.add(block('''
            if __name__ == "__main__":
                if len(sys.argv) > 1 and sys.argv[1] == "test":
                    self_test()
                elif len(sys.argv) > 1 and sys.argv[1] == "server":
                    server_main()
                elif len(sys.argv) > 1 and sys.argv[1] == "client":
                    client_main(){{answers}}
                else:
                    main()
        ''').replace("{{answers}}", "" if not cfg["file_input"] else
                     '\n    elif len(sys.argv) > 2 and sys.argv[1] == "--answers":\n        run_from_file(sys.argv[2])'))
    elif cfg["file_input"]:
        prog.add(block('''
            if __name__ == "__main__":
                if len(sys.argv) > 1 and sys.argv[1] == "test":
                    self_test()
                elif len(sys.argv) > 2 and sys.argv[1] == "--answers":
                    run_from_file(sys.argv[2])
                else:
                    main()
        '''))
    else:
        prog.add(block('''
            if __name__ == "__main__":
                if len(sys.argv) > 1 and sys.argv[1] == "test":
                    self_test()
                else:
                    main()
        '''))
    return prog.render("\n".join(header))


def sample_value(rule, kind, i, default):
    """A value that obeys the rule (i makes it differ between rows)."""
    if kind == "int":
        low, high = rule.get("min"), rule.get("max")
        value = int(default)
        if low is not None and value < low:
            value = low + 10 * (i + 1)
        if high is not None and value > high:
            value = max(low if low is not None else 1, high - (2 - i))
        return str(value)
    if rule.get("examples"):
        return rule["examples"][i % len(rule["examples"])]
    if rule.get("allowed"):
        return rule["allowed"][i % len(rule["allowed"])]
    pattern = rule.get("pattern")
    value = {"digits": str(1001 + i), "letters": re.sub(r"[^A-Za-z]", "", default).upper()[:3] + "ABCDEFGHIJ"[i % 10],
             "alnum": default, "email": "user%d@mail.com" % (i + 1), "phone": "98765432%02d" % (i + 1),
             "date": "2026-01-%02d" % (i + 1)}.get(pattern, default)
    if "min_len" in rule and len(value) < rule["min_len"]:
        value = value[0] * (rule["min_len"] - len(value)) + value           # pad in front, keep the varying end
    if "max_len" in rule and len(value) > rule["max_len"]:
        value = value[-rule["max_len"]:]
    return value


def invalid_value(rule):
    """A value the rule must reject (to show the re-ask), or None if unsure."""
    if "min" in rule:
        return str(rule["min"] - 1)
    if "max" in rule:
        return str(rule["max"] + 1)
    if rule.get("allowed"):
        return "not-a-valid-choice"
    bad = {"digits": "abc", "letters": "123", "alnum": "a-b", "email": "not-an-email", "phone": "123",
           "date": "2026-13-45"}.get(rule.get("pattern"))
    if bad:
        return bad
    if rule.get("min_len", 0) > 1:
        return "x"
    if "max_len" in rule:
        return "x" * (rule["max_len"] + 1)
    return None


def build_records_test(cfg):
    fields, ops, search = cfg["fields"], cfg["he"], cfg["search"]
    index_fields, methods, used = cfg["index_fields"], cfg["methods"], cfg["used"]
    votes_op = [op for op in ops if op["type"] == "votes"]
    vote_pattern = [0, 1, 0]
    samples = []
    for i in range(3):
        row = {}
        for f in fields:
            if f["kind"] == "choice":
                choices = votes_op[0]["choices"]
                row[f["var"]] = choices[vote_pattern[i] % len(choices)]
            elif f["kind"] == "int":
                row[f["var"]] = str(10 * (i + 1))
            elif f["kind"] == "file":
                row[f["var"]] = None
            else:
                letters = re.sub(r"[^A-Za-z]", "", f["label"]).upper()[:3] or "VAL"
                row[f["var"]] = letters + str(i % 2 + 1)        # rows 1 and 3 share a value (for filters)
        samples.append(row)
    ids = ["R1", "R2", "R3"]
    rules = cfg["rules"]
    for f in fields:
        if f["label"] in rules:
            for i in range(3):
                samples[i][f["var"]] = sample_value(rules[f["label"]], f["kind"], i % 2 if f["kind"] == "text" else i,
                                                    samples[i][f["var"]])
    if cfg["id_label"] in rules:
        ids = [sample_value(rules[cfg["id_label"]], "text", i, ids[i]) for i in range(3)]
        if len(set(ids)) < 3:
            sys.exit("generate.py: the %s rule allows fewer than 3 different IDs for the self-test -- add examples"
                     % cfg["id_label"])
    key_answer = [q("examkey123")] if cfg["key_src"] == "typed_each" else []
    signers = ["Alice", "Bob", "Alice"]

    def key_for(i):
        if cfg["key_src"] == "password":
            return [q("pw-R%d" % (i + 1))]
        return key_answer

    def add_answers(i):
        out = [q(ids[i])]
        bad = invalid_value(rules[cfg["id_label"]]) if i == 0 and cfg["id_label"] in rules else None
        if bad is not None:
            out.insert(0, q(bad))                       # first a value the rule must reject
        for f in fields:
            if i == 0 and f["label"] in rules:
                bad = invalid_value(rules[f["label"]])
                if bad is not None:
                    out.append(q(bad))
            out.append("sample_file" if f["kind"] == "file" else q(samples[i][f["var"]]))
        if cfg["extra"]:
            out.append(q("AUTH%d" % (i + 1)))
        out += key_for(i)
        if cfg["iv_src"] == "typed":
            out.append(q("initvector%d" % (i + 1)))
        if cfg["user_keys"] and not cfg["login"]:
            out.append(q(signers[i]))
        return out

    def query_answers(method, field_label, value):
        out = [q(method)] if len(methods) > 1 else []
        choices = ([cfg["id_label"]] + index_fields) if method == "plain" else index_fields
        if len(choices) > 1:
            out.append(q(field_label))
        return out + [q(value)]

    def expected(op, rows):
        if op["type"] == "votes":
            return "{%s}" % ", ".join("%s: %d" % (q(c), sum(1 for i in rows if samples[i][op["var"]] == c))
                                      for c in op["choices"])
        kind, k = op["type"], 3
        values = [int(samples[i][op["var"]]) for i in rows]
        product = 1
        for v in values:
            product *= v
        if kind in ("sum", "eg_sum"):
            return str(sum(values))
        if kind == "average":
            return repr(sum(values) / len(values))
        if kind == "scaled_sum":
            return str(k * sum(values))
        if kind in ("product", "eg_product"):
            return str(product)
        if kind in ("scaled_product", "eg_scaled_product"):
            return str(k * product)
        each = {"add_const": lambda v: v + k, "scale_each": lambda v: k * v, "rsa_scale_each": lambda v: k * v,
                "eg_scale_each": lambda v: k * v, "rsa_power": lambda v: v ** k, "eg_power": lambda v: v ** k,
                "compare": lambda v: v > 15}[kind]
        return "{%s}" % ", ".join("%s: %r" % (q(ids[i]), each(int(samples[i][op["var"]]))) for i in rows)

    def extra(op):
        if op["type"] in NEEDS_K:
            return [q("3")]
        return [q("15")] if op["type"] == "compare" else []

    t = ["# ---------- self-test:  python %s test ----------" % os.path.basename(cfg["out"]), "",
         "def self_test():",
         "    import builtins",
         "    import tempfile"]
    files = ["RECORDS_FILE", "LOG_FILE"]
    if cfg["persist"]:
        files.append("KEYS_FILE")
    if cfg["wrap"] == "file":
        files.append("WRAPPED_KEY_FILE")
    decrypted = cfg["decrypted_file"] and "decrypt" in used
    if decrypted:
        files.append("DECRYPTED_FILE")
    if "report" in used:
        files.append("REPORT_FILE")
    if cfg["login"]:
        files.append("USERS_FILE")
    if cfg["user_keys"] and cfg["persist"]:
        files.append("SIGNER_KEYS_FILE")
    if index_fields:
        files.append("PLAIN_INDEX_FILE")
    if "sse" in cfg["index_types"]:
        files.append("SSE_INDEX_FILE")
    if "pkse" in cfg["index_types"]:
        files.append("PKSE_INDEX_FILE")
    extra_globals = (["CURRENT_USER"] if cfg["login"] or cfg["user_keys"] else []) + (["PORT"] if cfg["sockets"] else [])
    t += ["    global " + ", ".join(files + extra_globals), "", "    tmp = tempfile.mkdtemp()"]
    for name in files:
        t.append('    %s = os.path.join(tmp, "%s.txt")' % (name, name[:-5].lower()))
    if any(f["kind"] == "file" for f in fields):
        t += ['    sample_file = os.path.join(tmp, "sample.txt")',
              '    with open(sample_file, "w", encoding="utf-8") as f:',
              '        f.write("Sample document\\nLine two of the file\\n")']
    if "search_time" in used:
        t += ['    hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")',
              '    hour_later = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")']
    t += ["",
          "    queue = []",
          "",
          '    def fake_input(prompt=""):',
          "        if not queue:",
          '            raise RuntimeError("self-test has no answer for the prompt " + repr(prompt))',
          "        answer = queue.pop(0)",
          "        print(prompt + answer)",
          "        return answer",
          "",
          "    builtins.input = fake_input",
          "",
          "    def run(fn, *answers):",
          "        queue[:] = list(answers)",
          '        print("\\n>>>", fn.__name__, answers)',
          "        return fn()",
          ""]
    setup_answers = []
    if cfg["key_src"] == "typed_once":
        setup_answers.append(q("examkey123"))
    if cfg["window"]:
        setup_answers += [q(""), q("")]
    if cfg["decrypt_window"]:
        setup_answers += [q(""), q("")]
    t += ["    queue[:] = [%s]" % ", ".join(setup_answers), "    setup_keys()", ""]
    if cfg["login"]:
        t += ['    assert run(lambda: login("Tester"), "alice", "y", "pw-alice") == "alice"      # register',
              '    assert run(lambda: login("Tester"), "alice", "no", "nope", "wrong") is None   # 3 wrong passwords',
              '    assert run(lambda: login("Tester"), "alice", "pw-alice") == "alice"           # correct password',
              '    assert run(lambda: login("Tester"), "zed", "n") is None                       # unknown, not registered',
              '    assert "pw-alice" not in open(USERS_FILE, encoding="utf-8").read()            # never stored',
              '    CURRENT_USER = "alice"', ""]
    for i in range(3):
        t.append("    run(add_record, %s)" % ", ".join(add_answers(i)))
    t += ["    run(add_record, %s)                       # duplicate ID is refused" % q(ids[0]),
          "    assert len(load_records()) == 3",
          "    assert all(is_valid(rec) for rec in load_records())"]
    if cfg["persist"]:
        t += ["",
              "    # restart: keys come back from KEYS_FILE, old records must still verify",
              "    K.clear()"] + (["    USER_KEYS.clear()"] if cfg["user_keys"] else []) + [
              "    queue[:] = []",
              "    setup_keys()",
              "    assert all(is_valid(rec) for rec in load_records())",
              ""]
    if "verify_one" in used:
        t.append("    assert run(verify_one, %s) is True" % q(ids[0]))
    for a_, call in (("view", "view_all"), ("view_meta", "view_meta"), ("verify", "verify_all")):
        if a_ in used:
            t.append("    run(%s)" % call)
    if "decrypt" in used:
        t.append("    assert run(decrypt_one, %s) is not None" % ", ".join([q(ids[0])] + key_for(0)))
        if decrypted:
            t.append('    assert len(open(DECRYPTED_FILE, encoding="utf-8").read().splitlines()) == 1')
        if cfg["key_src"] == "password":
            t.append('    assert run(decrypt_one, "R1", "not-the-password") is None             # wrong password refused')
        if cfg["decrypt_window"]:
            t += ['    saved_end = K["dend"]',
                  '    K["dend"] = "2000-01-01 00:00"                                       # window already over',
                  '    assert run(decrypt_one, "R1") is None',
                  '    K["dend"] = saved_end']
        if decrypted and (cfg["key_src"] == "password" or cfg["decrypt_window"]):
            t.append('    assert len(open(DECRYPTED_FILE, encoding="utf-8").read().splitlines()) == 1   # refusals not written')
    if "report" in used:
        t.append("    assert run(compliance_report) == 3")

    filter_rows = None
    if index_fields:
        f0 = field_by_label(cfg, index_fields[0])
        value = samples[0][f0["var"]]
        filter_rows = [i for i in range(3) if samples[i][f0["var"]].lower() == value.lower()]
    if "search" in used:
        for method in methods:
            t.append("    assert run(search_records, %s) == %s"
                     % (", ".join(query_answers(method, f0["label"], value)), json.dumps([ids[i] for i in filter_rows])))
        t.append("    assert run(search_records, %s) == []"
                 % ", ".join(query_answers(methods[-1], f0["label"], "nothing-like-this")))
        if "plain" in methods:
            t.append("    assert run(search_records, %s) == [\"R2\"]" % ", ".join(query_answers("plain", cfg["id_label"], "R2")))
    if "search_time" in used:
        for method in cfg["time_methods"]:
            ans = ([q(method)] if len(cfg["time_methods"]) > 1 else []) + ["hour_ago", "hour_later"]
            t.append("    assert run(search_time_range, %s) == %s" % (", ".join(ans), json.dumps(ids)))
    for op in ops:
        if op["action"] not in used:
            continue
        if op["type"] == "difference":
            diff = int(samples[2][op["var"]]) - int(samples[0][op["var"]])
            t.append('    assert run(%s, "R3", "R1") == %d' % (op["action"], diff))
            t.append('    assert run(%s, "R1", "R3") == %d                # negative result' % (op["action"], -diff))
            continue
        more = extra(op)
        if op["select"] == "ask":
            t.append("    assert run(%s) == %s                      # menu: all"
                     % (", ".join([op["action"], q("1")] + more), expected(op, [0, 1, 2])))
            t.append("    assert run(%s) == %s          # menu: chosen IDs"
                     % (", ".join([op["action"], q("2"), q("R1, R3")] + more), expected(op, [0, 2])))
            if index_fields:
                method = methods[-1]
                t.append("    assert run(%s) == %s          # menu: filter %s via %s"
                         % (", ".join([op["action"], q("3")] + query_answers(method, f0["label"], value) + more),
                            expected(op, filter_rows), index_fields[0], method))
        elif op["select"] == "all":
            t.append("    assert run(%s) == %s                      # always all records"
                     % (", ".join([op["action"]] + more), expected(op, [0, 1, 2])))
        elif op["select"] == "ids":
            t.append("    assert run(%s) == %s          # typed IDs"
                     % (", ".join([op["action"], q("R1, R3")] + more), expected(op, [0, 2])))
        else:
            ff = field_by_label(cfg, op["filter_field"])
            v = samples[0][ff["var"]]
            rows = [i for i in range(3) if samples[i][ff["var"]].lower() == v.lower()]
            t.append("    assert run(%s) == %s          # fixed filter %s via %s"
                     % (", ".join([op["action"], q(v)] + more), expected(op, rows), ff["label"], op["filter_method"]))
    if "cosign" in used:
        if cfg["login"]:
            t += ['    CURRENT_USER = "carol"', '    assert run(cosign_record, "R1") is True',
                  '    assert run(cosign_record, "R1") is None                         # carol cannot sign twice',
                  '    CURRENT_USER = "alice"']
            who = "carol"
        else:
            t += ['    assert run(cosign_record, "R1", "Bob") is True',
                  '    assert run(cosign_record, "R1", "Alice") is None                # Alice already signed']
            who = "Bob"
        t += ['    assert is_valid(find_record("R1"))',
              '    assert "countersignature %s" in check_record(find_record("R1"))' % who]
    if "show_keys" in used:
        t.append("    run(show_keys)")
    if cfg["user_keys"]:
        t += ['    forged = dict(find_record("R3"))',
              '    forged["signer"] = "Bob" if forged["signer"] != "Bob" else "Alice"    # claim someone else signed',
              '    assert not is_valid(forged)']
    t += ["",
          "    # tamper with R2: every check must now refuse it",
          '    run(tamper_record, "R2")',
          '    assert not is_valid(find_record("R2"))']
    if "verify" in used:
        t.append("    run(verify_all)")
    if "verify_one" in used:
        t.append('    assert run(verify_one, "R2") is False                  # tampered -> INVALID, nothing shown')
    if "decrypt" in used:
        t.append('    assert run(decrypt_one, "R2") is None')
        if decrypted:
            t.append('    assert len(open(DECRYPTED_FILE, encoding="utf-8").read().splitlines()) == 1   # refused -> not written')
    if "report" in used:
        t.append("    assert run(compliance_report) == 2")
    for op in ops:
        if op["action"] in used and op["type"] == "difference":
            t.append('    assert run(%s, "R2", "R1") is None              # tampered R2 refused' % op["action"])
        elif op["action"] in used:
            if op["select"] == "filter":
                ff = field_by_label(cfg, op["filter_field"])
                v = samples[0][ff["var"]]
                rows = [i for i in range(3) if i != 1 and samples[i][ff["var"]].lower() == v.lower()]
                answers, rows_after = [q(v)], rows
            else:
                answers = {"ask": [q("1")], "all": [], "ids": [q("R1, R2, R3")]}[op["select"]]
                rows_after = [0, 2]
            t.append("    assert run(%s) == %s                 # R2 no longer counted"
                     % (", ".join([op["action"]] + answers + extra(op)), expected(op, rows_after)))
    if cfg["file_input"] and "import" in used:
        new_id = sample_value(rules[cfg["id_label"]], "text", 4, "R9") if cfg["id_label"] in rules else "R9"
        values = [q(new_id)]
        for f in fields:
            values.append("sample_file" if f["kind"] == "file" else q(samples[1][f["var"]]))
        if cfg["extra"]:
            values.append(q("AUTH9"))
        if cfg["key_src"] == "typed_each":
            values.append(q("examkey123"))
        if cfg["key_src"] == "password":
            values.append(q("pw-new"))
        if cfg["iv_src"] == "typed":
            values.append(q("initvector9"))
        if cfg["user_keys"] and not cfg["login"]:
            values.append(q("Alice"))
        lines = ['"# a comment line is skipped"',
                 "IMPORT_SEPARATOR.join([%s])" % ", ".join(values),                         # good
                 "IMPORT_SEPARATOR.join([%s])" % ", ".join([q(ids[0])] + values[1:]),        # duplicate ID
                 '"only" + IMPORT_SEPARATOR + "two"']                                          # wrong count
        bad_field = None
        for f in fields:
            if f["label"] in rules and invalid_value(rules[f["label"]]) is not None:
                bad_field = f
                break
        if bad_field is not None:
            bad_values = list(values)
            bad_values[0] = q(sample_value(rules[cfg["id_label"]], "text", 5, "R8")
                              if cfg["id_label"] in rules else "R8")          # a fresh, valid ID
            bad_values[1 + fields.index(bad_field)] = q(invalid_value(rules[bad_field["label"]]))
            lines.append("IMPORT_SEPARATOR.join([%s])" % ", ".join(bad_values))              # breaks a rule
        t += ["",
              "    # import from a .txt file: 1 good line, a duplicate, a wrong count%s"
              % (", a rule violation" if bad_field is not None else ""),
              '    import_file = os.path.join(tmp, "import.txt")',
              '    with open(import_file, "w", encoding="utf-8") as f:',
              '        f.write("\\n".join([%s]) + "\\n")' % ", ".join(lines),
              "    before = len(load_records())",
              "    assert import_records(import_file) == [%s]" % q(new_id),
              "    assert len(load_records()) == before + 1",
              "    assert is_valid(find_record(%s))" % q(new_id)]
    if cfg["sockets"]:
        t += ["",
              "    # sockets: a server thread receives a good record, a tampered copy and a duplicate",
              "    import threading",
              "    good = find_record(\"R1\")",
              "    bad = dict(good)",
              '    bad["enc"] = bad["enc"][:-1] + ("0" if bad["enc"][-1] != "0" else "1")',
              "    probe = socket.socket()",
              "    probe.bind((HOST, 0))",
              "    PORT = probe.getsockname()[1]",
              "    probe.close()",
              '    RECORDS_FILE = os.path.join(tmp, "server_records.txt")',
              "    ready = threading.Event()",
              "    server = threading.Thread(target=server_loop, args=(3, ready))",
              "    server.start()",
              "    ready.wait()",
              '    assert send_record(good).startswith("ACK")',
              '    assert send_record(bad).startswith("REJECTED")',
              '    assert send_record(good).startswith("REJECTED")                # duplicate ID',
              "    server.join()",
              "    assert len(load_records()) == 1"]
    t += ["", '    print("\\nSELF-TEST PASSED")']
    text = "\n".join(t)
    if ids != ["R1", "R2", "R3"]:                       # constrained IDs: use the valid sample IDs everywhere
        for number in (1, 2, 3):
            text = re.sub(r'(?<=["\s,\[])R%d(?=["\],])' % number, ids[number - 1], text)
    return text


# =============================================================================
#  2. key exchange + classical cipher (FieldTrack style)
# =============================================================================

KX_DEFAULTS = {
    "name": "FieldTrack",
    "out": "fieldtrack.py",
    "p": 23, "g": 5,                       # TODO numbers from the question
    "sender_private": 6, "receiver_private": 15,   # None -> random
    "cipher": "affine",                    # affine | additive | multiplicative
    "k2": 2,                               # affine: None -> k2 = K mod 26, else check K mod 26 == k2
}


def build_kx(cfg):
    cfg = dict(KX_DEFAULTS, **cfg)
    cipher = cfg["cipher"]
    prog = Program()
    header = "\n".join([
        "# %s  --  generated by reference/generate.py" % cfg["name"],
        "#",
        "# Sender and Receiver agree on a Diffie-Hellman shared secret K (and check",
        "# that both computed the same K), then use it for a %s cipher on" % cipher,
        "# UPPERCASE A-Z text (everything else is removed first).",
        {"affine": "#   C = (k1 * P + k2) mod 26     P = (k1^-1 * (C - k2)) mod 26\n"
                   "#   k2 %s; k1 is typed and must satisfy gcd(k1, 26) = 1\n"
                   "#   (an invalid k1 is discarded and asked for again)."
                   % ("= K mod 26" if cfg["k2"] is None else "is given and must equal K mod 26"),
         "additive": "#   C = (P + k) mod 26 with k = K mod 26",
         "multiplicative": "#   C = (k1 * P) mod 26, k1 typed, gcd(k1, 26) must be 1"}[cipher],
        "#",
        "# Run:  python %s         python %s test" % (os.path.basename(cfg["out"]), os.path.basename(cfg["out"]))])

    prog.use("dh.py", "dh_generate_keypair", "compute_shared_secret")
    prog.add(fill(r'''
        # ---------- adapted from ciphers/primitives.py: UPPERCASE alphabet ----------

        A = string.ascii_uppercase


        def clean(text):
            """Uppercase, keep A-Z only."""
            return "".join(c for c in text.upper() if c in A)


        def affine_encrypt(text, a, b):
            return "".join(A[(a * A.index(c) + b) % 26] for c in text)


        def affine_decrypt(text, a, b):
            inv = pow(a, -1, 26)
            return "".join(A[(inv * (A.index(c) - b)) % 26] for c in text)
    '''), "import string", "import math", "import sys")

    priv = lambda v: "None" if v is None else str(v)
    consts = ["# ==================== EDIT ZONE: the numbers given in the question ====================", "",
              "P = %d                       # TODO: DH prime p" % cfg["p"],
              "G = %d                        # TODO: DH generator g" % cfg["g"],
              "SENDER_PRIVATE = %s          # TODO: None -> random" % priv(cfg["sender_private"]),
              "RECEIVER_PRIVATE = %s        # TODO: None -> random" % priv(cfg["receiver_private"])]
    if cipher == "affine":
        consts.append("K2 = %s                       # TODO: k2 given in the question (None -> k2 = K mod 26)" % priv(cfg["k2"]))
    prog.add("\n".join(consts))

    body = [block(r'''
        def private_key(given):
            if given is not None:
                return given, pow(G, given, P)
            public, private = dh_generate_keypair(P, G)
            return private, public


        def key_exchange():
            print("Public parameters: p =", P, " g =", G)
            a, sender_public = private_key(SENDER_PRIVATE)
            b, receiver_public = private_key(RECEIVER_PRIVATE)
            print("Sender   private a =", a, " public A = g^a mod p =", sender_public)
            print("Receiver private b =", b, " public B = g^b mod p =", receiver_public)

            sender_secret = compute_shared_secret(receiver_public, a, P)       # B^a mod p
            receiver_secret = compute_shared_secret(sender_public, b, P)       # A^b mod p
            print("Sender   computes K = B^a mod p =", sender_secret)
            print("Receiver computes K = A^b mod p =", receiver_secret)
            if sender_secret != receiver_secret:
                print("FAILURE: the shared secrets differ -- stopping.")
                return None, None
            print("Shared secrets match: K =", sender_secret)
            return sender_secret, receiver_secret
    ''')]
    if cipher in ("affine", "multiplicative"):
        body.append(block(r'''
            def ask_k1(who):
                """Asks until k1 is a whole number with gcd(k1, 26) = 1; invalid values are discarded."""
                while True:
                    s = input(who + ": enter k1 (gcd(k1, 26) must be 1): ").strip()
                    try:
                        k1 = int(s)
                    except ValueError:
                        print("  INVALID: k1 must be a whole number -- discarded.")
                        continue
                    if math.gcd(k1, 26) != 1:
                        print("  INVALID: gcd(" + str(k1) + ", 26) =", math.gcd(k1, 26), "-> no inverse mod 26, k1 discarded.")
                        continue
                    inverse = pow(k1, -1, 26)
                    print("  k1 =", k1, "accepted. Inverse of k1 mod 26 =", inverse,
                          "(check:", k1, "*", inverse, "mod 26 =", (k1 * inverse) % 26, ")")
                    return k1
        '''))
    if cipher == "affine":
        body.append(block(r'''
            def get_k2(who, K):
                print(who + ": K mod 26 =", K % 26)
                if K2 is None:
                    print("  k2 = K mod 26 =", K % 26)
                    return K % 26
                if K % 26 != K2:
                    print("  FAILURE: K mod 26 =", K % 26, "but k2 =", K2, "-- keys do not match, stopping.")
                    return None
                print("  K mod 26 == k2 =", K2, "-> OK")
                return K2
        '''))
        enc_keys = ["    k2 = get_k2(who, K)", "    if k2 is None:", "        return None", "    k1 = ask_k1(who)"]
        enc_call, dec_call = "affine_encrypt(text, k1, k2)", "affine_decrypt(text, k1, k2)"
    elif cipher == "additive":
        enc_keys = ["    k = K % 26", '    print(who + ": k = K mod 26 =", k)', "    if k == 0:",
                    '        print("  FAILURE: k = 0 would leave the text unchanged -- stopping.")', "        return None"]
        enc_call, dec_call = "affine_encrypt(text, 1, k)", "affine_decrypt(text, 1, k)"
    else:
        enc_keys = ["    k1 = ask_k1(who)"]
        enc_call, dec_call = "affine_encrypt(text, k1, 0)", "affine_decrypt(text, k1, 0)"

    body.append("\n".join(["def sender_side(K):", '    who = "Sender"', '    print("\\n--- SENDER ---")'] + enc_keys + [
        '    text = clean(input("Sender: message: "))',
        "    if not text:",
        '        print("  FAILURE: no letters A-Z in the message -- nothing to encrypt.")',
        "        return None",
        '    print("  plaintext (A-Z only):", text)',
        "    ciphertext = " + enc_call,
        '    print("  ciphertext          :", ciphertext)',
        "    return text, ciphertext"]))
    body.append("\n".join(["def receiver_side(K, ciphertext):", '    who = "Receiver"', '    print("\\n--- RECEIVER ---")'] + enc_keys + [
        "    text = clean(ciphertext)",
        "    if text != ciphertext:",
        '        print("  FAILURE: ciphertext contains characters outside A-Z.")',
        "        return None",
        "    plaintext = " + dec_call,
        '    print("  decrypted plaintext :", plaintext)',
        "    return plaintext"]))
    body.append(block(r'''
        def main():
            sender_secret, receiver_secret = key_exchange()
            if sender_secret is None:
                return None
            sent = sender_side(sender_secret)
            if sent is None:
                return None
            plaintext, ciphertext = sent
            received = receiver_side(receiver_secret, ciphertext)
            if received is None:
                return None
            if received == plaintext:
                print("\nSUCCESS: the Receiver recovered exactly the Sender's message.")
            else:
                print("\nFAILURE: decrypted text differs from the original (different k1?).")
            return received


        def self_test():
            import builtins
            queue = []

            def fake_input(prompt=""):
                answer = queue.pop(0)
                print(prompt + answer)
                return answer

            builtins.input = fake_input
    '''))
    test = []
    if cipher in ("affine", "multiplicative"):
        test.append('    queue[:] = ["13", "abc", "5", "Field team at grid 7, move north!", "4", "5"]')
        if cipher == "affine":
            test.append('    expected = "FIELDTEAMATGRIDMOVENORTH" if SENDER_PRIVATE is not None and RECEIVER_PRIVATE is not None '
                        'and (K2 is None or pow(G, SENDER_PRIVATE * RECEIVER_PRIVATE, P) % 26 == K2) else None')
        else:
            test.append('    expected = "FIELDTEAMATGRIDMOVENORTH"')
    else:
        test.append('    queue[:] = ["Field team at grid 7, move north!"]')
        test.append('    expected = "FIELDTEAMATGRIDMOVENORTH" if SENDER_PRIVATE is not None and RECEIVER_PRIVATE is not None else None')
    test += ["    result = main()", "    if expected is not None:", "        assert result == expected, result",
             '    print("\\nSELF-TEST PASSED")']
    body[-1] = body[-1] + "\n" + "\n".join(test)
    prog.add("\n\n\n".join(body))
    prog.add(block('''
        if __name__ == "__main__":
            if len(sys.argv) > 1 and sys.argv[1] == "test":
                self_test()
            else:
                main()
    '''))
    return prog.render(header)


# =============================================================================
#  presets: the sample questions
# =============================================================================

PRESETS = {
    "evoting": {
        "_about": "E-voting: AES-256 ballot, RSA-4096 wrapped key, SHA-512, ElGamal sig, Paillier tally, "
                  "threshold decryption, plain/SSE/PKSE search by constituency + time, voting period",
        "name": "Secure E-Voting System", "out": "evoting.py", "noun": "ballot", "id_label": "Voter ID",
        "fields": "Candidate, Constituency",
        "enc": "aes256", "key_src": "wrap", "rsa_bits": 4096,
        "hash": "sha512", "hash_over": "plaintext", "sig": "elgamal",
        "he": [{"type": "votes", "field": "Candidate", "choices": ["Alice", "Bob", "Carol"], "select": "all"}],
        "trustees": 3,
        "search": {"types": ["sse", "pkse"], "fields": ["Constituency"], "time": True},
        "window": "voting period",
        "labels": {"add": "Cast ballot", "votes_candidate": "Tally votes (threshold-decrypt only the totals)"},
        "roles": [["Voter", ["add"]],
                  ["Election Server", ["verify", "view_meta", "search", "search_time"]],
                  ["Trustee Panel", ["tally"]],
                  ["Auditor", ["report", "view"]]],
    },
    "employee": {
        "_about": "Employee payroll: AES-256 + RSA sig + SHA-256, EVERY homomorphic operation (Paillier sum/average/"
                  "x k/+k/difference/threshold, RSA + ElGamal product/x k/power, exponential-ElGamal sum), "
                  "records by ID or department filter, plain/SSE/PKSE search",
        "name": "Secure Payroll System", "out": "payroll.py", "noun": "employee record", "id_label": "Employee ID",
        "fields": "Name, Department, Salary:int, Bonus factor:int",
        "enc": "aes256", "hash": "sha256", "sig": "rsa",
        # "select" = how each action picks its records: all | ids | filter (fixed field + index) | ask (menu)
        "he": [{"type": "sum", "field": "Salary", "select": "filter", "filter_field": "Department", "filter_method": "sse"},
               {"type": "average", "field": "Salary", "select": "ids"},
               {"type": "scaled_sum", "field": "Salary", "select": "all"},
               {"type": "add_const", "field": "Salary", "select": "ids"},
               {"type": "scale_each", "field": "Salary", "select": "ask"},
               {"type": "difference", "field": "Salary"},
               {"type": "compare", "field": "Salary", "select": "filter", "filter_field": "Department", "filter_method": "plain"},
               {"type": "eg_sum", "field": "Salary", "select": "all"},
               {"type": "product", "field": "Bonus factor", "select": "filter", "filter_field": "Department",
                "filter_method": "pkse"},
               {"type": "scaled_product", "field": "Bonus factor", "select": "ids"},
               {"type": "rsa_scale_each", "field": "Bonus factor", "select": "ids"},
               {"type": "rsa_power", "field": "Bonus factor", "select": "ask"},
               {"type": "eg_product", "field": "Bonus factor", "select": "all"},
               {"type": "eg_scaled_product", "field": "Bonus factor", "select": "ids"},
               {"type": "eg_scale_each", "field": "Bonus factor", "select": "filter", "filter_field": "Name"},
               {"type": "eg_power", "field": "Bonus factor", "select": "ids"}],
        "search": {"types": ["sse", "pkse"], "fields": ["Department", "Name"], "time": True},
        "roles": [["HR", ["add", "view"]],
                  ["Manager", ["verify", "decrypt", "search", "sum_salary", "average_salary", "compare_salary"]],
                  ["Finance", ["tally"]],
                  ["Auditor", ["report", "view_meta", "search_time"]]],
    },
    "securevault": {
        "_about": "SecureVault: DES-CBC + IV, SHA-256 of ciphertext, ElGamal sig; Client / Lawyer / Compliance Officer",
        "name": "SecureVault", "out": "securevault.py", "noun": "document", "id_label": "Case ID",
        "fields": "Client Name, Document",
        "enc": "des", "key_src": "random", "iv_src": "random",
        "hash": "sha256", "hash_over": "ciphertext", "sig": "elgamal",
        "roles": [["Client", ["add", "view"]],
                  ["Lawyer", ["decrypt", "view"]],
                  ["Compliance Officer", ["verify", "report", "view_meta"]]],
    },
    "healthsecure": {
        "_about": "HealthSecure: RSA-encrypted patient fields, SHA-256 of ciphertext, RSA sig; Doctor / Nurse / Admin",
        "name": "HealthSecure", "out": "healthsecure.py", "noun": "patient record", "id_label": "Patient ID",
        "fields": "Name, Diagnosis, Treatment",
        "enc": "rsa", "hash": "sha256", "hash_over": "ciphertext", "sig": "rsa",
        "roles": [["Doctor", ["add", "view", "decrypt"]],
                  ["Nurse", ["verify"]],
                  ["Admin", ["view_meta"]]],
    },
    "hospital": {
        "_about": "Hospital: file -> AES-128, AES key RSA-encrypted in a file, ElGamal auth code (given p,g,x), SHA-256, "
                  "sender/receiver hash check, tamper demo",
        "name": "Hospital Secure File Transfer", "out": "hospital.py", "noun": "file", "id_label": "File ID",
        "fields": "Report:file",
        "enc": "aes128", "key_src": "random", "wrap": "file",
        "extra": {"label": "Authorization code", "given": [7919, 2, 1234]},
        "hash": "sha256", "hash_over": "ciphertext", "sig": "none",
        "roles": [["Sender", ["add", "view"]],
                  ["Receiver", ["verify", "decrypt"]]],
    },
    "medisecure": {
        "_about": "MediSecure: AES with typed key + typed IV, SHA-256, RSA sig; Patient / Doctor / Auditor",
        "name": "MediSecure", "out": "medisecure_gen.py", "noun": "medical record", "id_label": "Patient ID",
        "fields": "Name, Symptoms",
        "enc": "aes128", "key_src": "typed_once", "iv_src": "typed",
        "hash": "sha256", "hash_over": "ciphertext", "sig": "rsa",
        "roles": [["Patient", ["add", "view"]],
                  ["Doctor", ["verify", "decrypt"]],
                  ["Auditor", ["view_meta", "report"]]],
    },
    "grant": {
        "_about": "Grant portal: AES-192 description, Paillier SUM of amount, MD5, RSA sig, SSE search by department",
        "name": "Secure Grant Expense Portal", "out": "grant_portal.py", "noun": "grant", "id_label": "Grant ID",
        "fields": "Department, Description, Amount:int",
        "enc": "aes192", "hash": "md5", "sig": "rsa",
        "he": [{"type": "sum", "field": "Amount", "select": "ids"}],
        "search": {"types": ["sse"], "fields": ["Department"], "time": False},
        "roles": [["Researcher", ["add", "view"]],
                  ["Reviewer", ["verify", "search", "decrypt"]],
                  ["Finance Officer", ["tally"]]],
    },
    # ---------- practice questions (guide/practice_questions.py, built in templates/practice/) ----------
    "pharmachain": {
        "_about": "Practice Q1 PharmaChain: AES-192 typed key, SHA-512, Schnorr; Manufacturer / Distributor / Regulator",
        "name": "PharmaChain", "out": "pharmachain.py", "noun": "drug batch", "id_label": "Batch ID",
        "fields": "Drug, Quantity:int, Expiry", "constraints": {"Expiry": {"pattern": "date"}, "Quantity": {"min": 1}},
        "enc": "aes192", "key_src": "typed_once", "hash": "sha512", "sig": "schnorr", "sign_time": False,
        "roles": [["Manufacturer", ["add", "view"]], ["Distributor", ["verify_one", "decrypt"]],
                  ["Regulator", ["verify", "report", "view_meta"]]],
    },
    "legaldocs": {
        "_about": "Practice Q2 LegalDocs: contract file -> 3DES, key RSA-encrypted in a file, MD5, DSA",
        "name": "LegalDocs", "out": "legaldocs.py", "noun": "contract", "id_label": "Contract ID",
        "fields": "Contract:file", "enc": "3des", "wrap": "file", "hash": "md5", "sig": "dsa", "sign_time": False,
        "roles": [["Client", ["add"]], ["Advocate", ["verify_one", "decrypt"]], ["Auditor", ["view_meta"]]],
    },
    "insureclaim": {
        "_about": "Practice Q3 InsureClaim: Paillier amounts, threshold check, region total/average, payout x k",
        "name": "InsureClaim", "out": "insureclaim.py", "noun": "claim", "id_label": "Claim ID",
        "fields": "Region, Description, Amount:int", "enc": "aes256", "wrap": "record", "sig": "rsa", "sign_time": False,
        "he": [{"type": "compare", "field": "Amount", "select": "ids"},
               {"type": "sum", "field": "Amount", "select": "filter", "filter_field": "Region"},
               {"type": "average", "field": "Amount", "select": "filter", "filter_field": "Region"},
               {"type": "scaled_sum", "field": "Amount", "select": "ids"}],
        "roles": [["Policyholder", ["add"]], ["Claims Officer", ["verify_one", "decrypt", "compare_amount"]],
                  ["Finance", ["sum_amount", "average_amount", "scaled_sum_amount"]]],
    },
    "courtevidence": {
        "_about": "Practice Q4 CourtEvidence: ECC, ElGamal signature, submission deadline, plain + SSE search",
        "name": "CourtEvidence", "out": "courtevidence.py", "noun": "evidence item", "id_label": "Evidence ID",
        "fields": "Case Number, Description", "enc": "ecc", "sig": "elgamal", "sign_time": False,
        "window": "submission deadline", "search": {"types": ["sse"], "fields": ["Case Number"], "time": False},
        "roles": [["Investigator", ["add"]], ["Judge", ["verify", "decrypt"]], ["Clerk", ["search", "view_meta"]]],
    },
    "payrollplus": {
        "_about": "Practice Q5 PayrollPlus: Paillier +k / department sum / difference, RSA + ElGamal products, power",
        "name": "PayrollPlus", "out": "payrollplus.py", "noun": "employee", "id_label": "Employee ID",
        "fields": "Name, Department, Salary:int, Multiplier:int", "enc": "aes256", "sig": "rsa", "sign_time": False,
        "he": [{"type": "add_const", "field": "Salary", "select": "filter", "filter_field": "Department"},
               {"type": "sum", "field": "Salary", "select": "filter", "filter_field": "Department"},
               {"type": "difference", "field": "Salary"},
               {"type": "product", "field": "Multiplier", "select": "all"},
               {"type": "eg_product", "field": "Multiplier", "select": "all"},
               {"type": "rsa_power", "field": "Multiplier", "select": "ids"}],
        "roles": [["HR", ["add", "view"]], ["Manager", ["add_const_salary", "sum_salary", "difference_salary"]],
                  ["Finance", ["product_multiplier", "eg_product_multiplier", "rsa_power_multiplier"]]],
    },
    "citypoll": {
        "_about": "Practice Q6 CityPoll: YES/NO/ABSTAIN ballots, 4 trustees, PKSE by ward, SSE by time, polling window",
        "name": "CityPoll", "out": "citypoll.py", "noun": "ballot", "id_label": "Voter ID",
        "fields": "Choice, Ward", "enc": "aes128", "wrap": "record", "hash_over": "plaintext", "sig": "rsa",
        "he": [{"type": "votes", "field": "Choice", "choices": ["YES", "NO", "ABSTAIN"], "select": "all"}],
        "trustees": 4, "search": {"types": ["sse", "pkse"], "fields": ["Ward"], "time": True},
        "window": "polling window",
        "roles": [["Voter", ["add"]], ["Returning Officer", ["verify", "view_meta", "search", "search_time"]],
                  ["Tally Committee", ["tally"]]],
    },
    "campusexam": {
        "_about": "Practice Q7 CampusExam: paper file, typed AES key RSA-encrypted in a file, decrypt only in exam window",
        "name": "CampusExam", "out": "campusexam.py", "noun": "question paper", "id_label": "Paper ID",
        "fields": "Paper:file", "enc": "aes256", "key_src": "typed_once", "wrap": "file", "sig": "none",
        "decrypt_window": "exam window",
        "roles": [["Exam Cell", ["add"]], ["Invigilator", ["verify_one", "decrypt"]], ["Student Portal", ["view_meta"]]],
    },
    "smartmeter": {
        "_about": "Practice Q8 SmartMeter: Paillier readings, zone total via PKSE filter, bill = total x k, > threshold",
        "name": "SmartMeter", "out": "smartmeter.py", "noun": "reading", "id_label": "Meter ID",
        "fields": "Zone, Reading:int", "hash": "sha1", "sig": "dsa", "sign_time": False,
        "he": [{"type": "sum", "field": "Reading", "select": "filter", "filter_field": "Zone", "filter_method": "pkse"},
               {"type": "average", "field": "Reading", "select": "ids"},
               {"type": "scaled_sum", "field": "Reading", "select": "ids"},
               {"type": "compare", "field": "Reading", "select": "all"}],
        "roles": [["Meter", ["add"]], ["Utility", ["verify", "tally"]]],
    },
    "bloodbank": {
        "_about": "Practice Q9 BloodBank: a password per donor record (PBKDF2), SSE search by blood group",
        "name": "BloodBank", "out": "bloodbank.py", "noun": "donor record", "id_label": "Donor ID",
        "fields": "Name, Blood Group, Medical Notes", "enc": "aes256", "key_src": "password", "sig": "rsa",
        "sign_time": False, "constraints": {"Blood Group": {"allowed": ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]}},
        "search": {"types": ["sse"], "fields": ["Blood Group"], "time": False},
        "roles": [["Donor", ["add"]], ["Doctor", ["verify_one", "decrypt"]], ["Admin", ["search", "view_meta"]]],
    },
    "researchvault": {
        "_about": "Practice Q10 ResearchVault: login, every researcher signs with their OWN RSA key, supervisor countersigns",
        "name": "ResearchVault", "out": "researchvault.py", "noun": "paper", "id_label": "Paper ID",
        "fields": "Title, Abstract", "enc": "aes256", "sig": "rsa", "sign_time": False,
        "user_keys": True, "cosign": True, "login": True,
        "roles": [["Researcher", ["add", "view"]], ["Supervisor", ["cosign", "verify"]],
                  ["Reviewer", ["verify", "decrypt", "show_keys"]]],
    },
    "tenderbid": {
        "_about": "Practice Q11 TenderBid: RSA-OAEP bids, ElGamal + exponential-ElGamal totals, reserve-price check",
        "name": "TenderBid", "out": "tenderbid.py", "noun": "bid", "id_label": "Bid ID",
        "fields": "Company, Amount:int", "enc": "rsa", "sig": "elgamal", "sign_time": False,
        "window": "bidding window",
        "he": [{"type": "eg_sum", "field": "Amount", "select": "all"},
               {"type": "eg_product", "field": "Amount", "select": "all"},
               {"type": "compare", "field": "Amount", "select": "all"}],
        "roles": [["Bidder", ["add"]], ["Committee", ["verify", "tally"]]],
    },
    "cipherrelay": {
        "_about": "Practice Q13 CipherRelay: socket client/server, AES-128 with RSA-wrapped key, SHA-256, RSA signature",
        "name": "CipherRelay", "out": "cipherrelay.py", "noun": "message", "id_label": "Message ID",
        "fields": "Message", "enc": "aes128", "wrap": "record", "sig": "rsa", "sign_time": False, "sockets": True,
    },
    "fieldtrack": {
        "_about": "FieldTrack: DH shared secret (p=23, g=5), affine cipher with k2 = 2 checked against K mod 26, k1 validated",
        "_kind": "kx",
        "name": "FieldTrack", "out": "fieldtrack.py",
        "p": 23, "g": 5, "sender_private": 6, "receiver_private": 15, "cipher": "affine", "k2": 2,
    },
}


# =============================================================================
#  the questions
# =============================================================================

def ask(prompt, default=""):
    s = input("%s [%s]: " % (prompt, default)).strip()
    return s if s else str(default)


def ask_num(prompt, default):
    while True:
        s = ask(prompt, default)
        try:
            return int(s)
        except ValueError:
            print("  a whole number please")


def pick(prompt, options, default):
    """options: list of (value, text). Returns the value."""
    print(prompt)
    for i, (value, text) in enumerate(options, start=1):
        print("  %d) %s" % (i, text))
    while True:
        s = ask("  choice", default)
        if s.isdigit() and 1 <= int(s) <= len(options):
            return options[int(s) - 1][0]
        for value, _ in options:
            if s.lower() == str(value).lower():
                return value
        print("  pick a number from the list")


def yes(prompt, default="n"):
    return ask(prompt + " (y/n)", default).lower().startswith("y")


def ask_fields(prompt, labels):
    """Field names or their numbers, comma separated; asks again until every one exists."""
    print(prompt + ": " + ", ".join("%d=%s" % (i, l) for i, l in enumerate(labels, start=1)))
    while True:
        chosen = []
        for part in ask("  names or numbers, comma separated", "1").split(","):
            part = part.strip()
            if part.isdigit() and 1 <= int(part) <= len(labels):
                chosen.append(labels[int(part) - 1])
            elif part.lower() in [l.lower() for l in labels]:
                chosen.append(next(l for l in labels if l.lower() == part.lower()))
            elif part:
                print("  no field called", repr(part))
                chosen = None
                break
        if chosen:
            return chosen


def ask_constraints(id_label, fields):
    labels = [id_label] + [f["label"] for f in fields if f["kind"] != "file"]
    chosen = ask_fields("  which fields have constraints", labels)
    kinds = {f["label"]: f["kind"] for f in fields}
    rules = {}
    for label in chosen:
        rule = {}
        if kinds.get(label) == "int":
            print("  %s is a number:" % label)
            low, high = ask("    minimum (Enter = none)", ""), ask("    maximum (Enter = none)", "")
            if low.strip():
                rule["min"] = int(low)
            if high.strip():
                rule["max"] = int(high)
        else:
            kind = pick("  rule for %s:" % label, [
                ("any", "any characters (only a length limit)"), ("letters", "letters only"),
                ("digits", "digits only"), ("alnum", "letters and digits only"), ("email", "email address"),
                ("phone", "10-digit phone number"), ("date", "date YYYY-MM-DD"),
                ("allowed", "one of a fixed list of values"), ("regex", "custom pattern (regex)")], 1)
            if kind == "allowed":
                rule["allowed"] = [v.strip() for v in ask("    allowed values, comma separated", "A, B, C").split(",") if v.strip()]
            elif kind == "regex":
                rule["pattern"] = ask("    regex the WHOLE value must match", "[A-Z]{2}[0-9]{4}")
                rule["examples"] = [v.strip() for v in ask("    3 valid example values (for the self-test)",
                                                           "AB1234, CD5678, EF9012").split(",") if v.strip()]
            elif kind != "any":
                rule["pattern"] = kind
            if kind not in ("allowed", "date", "phone"):
                low, high = ask("    minimum length (Enter = none)", ""), ask("    maximum length (Enter = none)", "")
                if low.strip():
                    rule["min_len"] = int(low)
                if high.strip():
                    rule["max_len"] = int(high)
        if rule:
            rules[label] = rule
    return rules


def ask_given(prompt):
    s = ask(prompt + " -- type p,g,x or Enter to generate", "")
    if not s:
        return None
    p, g, x = (int(v) for v in s.replace(" ", "").split(","))
    return [p, g, x]


def interview_records():
    cfg = {}
    cfg["name"] = ask("System name", DEFAULTS["name"])
    cfg["noun"] = ask("What is ONE stored item called (record, ballot, document, ...)", "record")
    cfg["id_label"] = ask("Name of its ID field (asked separately -- don't list it again below)", "Record ID")
    print("OTHER data fields to encrypt, comma separated. Add :int for numbers, :file to read a .txt file.")
    cfg["fields"] = ask("  fields", "Name, Details")
    fields = parse_fields(cfg["fields"])
    if yes("Any CONSTRAINTS on the fields (digits only, length, allowed values, number range...)?"):
        cfg["constraints"] = ask_constraints(cfg["id_label"], fields)

    cfg["enc"] = pick("Encrypt the data with:", [("aes128", "AES-128"), ("aes192", "AES-192"), ("aes256", "AES-256"),
                                                ("des", "DES (CBC, with IV)"), ("3des", "Triple DES"),
                                                ("rsa", "RSA (OAEP, short data only)"), ("elgamal", "ElGamal"),
                                                ("ecc", "ECC"), ("rabin", "Rabin")], 3)
    if cfg["enc"] in SYMMETRIC:
        cfg["key_src"] = pick("Where does the key come from?", [
            ("random", "random, generated by the program"),
            ("typed_once", "typed by the user once at start-up"),
            ("typed_each", "typed by the user when encrypting AND when decrypting"),
            ("password", "a password the user sets for EACH record (PBKDF2; salt + check stored, never the password)")], 1)
        cfg["wrap"] = "none" if cfg["key_src"] == "password" else pick("Encrypt the key with RSA?", [
            ("none", "no"),
            ("record", "yes -- a FRESH random key per record, RSA-encrypted and stored in the record (hybrid)"),
            ("file", "yes -- ONE key, RSA-encrypted and saved to its own file (receiver unwraps it)")], 1)
        if cfg["wrap"] != "none":
            cfg["rsa_bits"] = ask_num("RSA key size for encrypting the key", 2048)
        if cfg["enc"] != "3des":
            cfg["iv_src"] = pick("IV:", [("random", "random per record"), ("typed", "typed by the user")], 1)
    if cfg["enc"] == "rsa":
        cfg["rsa_bits"] = ask_num("RSA key size", 2048)
    if cfg["enc"] == "elgamal":
        cfg["elgamal_given"] = ask_given("ElGamal parameters given in the question?")
    if yes("Encrypt some fields with a DIFFERENT algorithm (e.g. Diagnosis with RSA)?"):
        own = ask_fields("  which fields get their own algorithm", [f["label"] for f in fields])
        cfg["field_enc"] = {}
        for label in own:
            cfg["field_enc"][label] = pick("  algorithm for %s:" % label, [
                ("aes128", "AES-128"), ("aes192", "AES-192"), ("aes256", "AES-256"), ("des", "DES (CBC)"),
                ("3des", "Triple DES"), ("rsa", "RSA (OAEP)"), ("elgamal", "ElGamal"), ("ecc", "ECC"),
                ("rabin", "Rabin")], 6)

    cfg["hash"] = pick("Hash:", [("sha256", "SHA-256"), ("sha512", "SHA-512"), ("sha1", "SHA-1"), ("md5", "MD5")], 1)
    cfg["hash_over"] = pick("Hash of:", [("ciphertext", "the ciphertext (can be checked without decrypting)"),
                                         ("plaintext", "the plaintext (receiver decrypts, then re-hashes)")], 1)
    cfg["sig"] = pick("Digital signature:", [(k, v) for k, v in SIGNATURES.items()], 2)
    if cfg["sig"] != "none":
        cfg["sign_time"] = yes("  sign the hash TOGETHER with the timestamp (hash|timestamp)? 'n' = only the hash", "n")
    if cfg["sig"] != "none" and yes("Does every user sign with their OWN key pair (record stores who signed)?"):
        cfg["user_keys"] = True
        cfg["cosign"] = yes("  add a 'Countersign' action (a second user signs too)?")

    if yes("A separate small value encrypted with ElGamal (e.g. an authorization code)?"):
        cfg["extra"] = {"label": ask("  its name", "Authorization code"),
                        "given": ask_given("  ElGamal parameters for it given?")}

    ops = []
    print("Homomorphic operations (lab 7) -- add as many as you need, each becomes its own menu action.")
    print("  (not possible with these schemes: Paillier ct*ct, RSA addition, plain-ElGamal addition)")
    while True:
        kind = pick("  add an operation:", [("done", "done / none")] + [(k, v) for k, v in HE_TYPES.items()], 1)
        if kind == "done":
            break
        candidates = [f["label"] for f in fields if f["kind"] != "file"]
        field = pick("    on which field?", [(l, l) for l in candidates], 1)
        op = {"type": kind, "field": field}
        if kind == "votes":
            op["choices"] = [c.strip() for c in ask("    the options / candidates", "Alice, Bob, Carol").split(",") if c.strip()]
        if kind != "difference":
            op["select"] = pick("    which records should the role's action use?", [
                ("all", "always ALL records (no question asked)"),
                ("ids", "the role types a list of IDs"),
                ("filter", "the role types a value for a FIXED field filter (e.g. Department = HR)"),
                ("ask", "let the role choose each time (all / IDs / filter menu)")], 2)
            if op["select"] == "filter":
                op["filter_field"] = pick("      filter on which field?",
                                          [(l, l) for l in candidates if l != field] or [(field, field)], 1)
                op["filter_method"] = pick("      through which index?", [("plain", "plain index (stored in clear)"),
                                                                         ("sse", "SSE (HMAC tokens)"),
                                                                         ("pkse", "PKSE (Paillier)")], 1)
        ops.append(op)
        print("    added:", HE_TYPES[kind], "of", field, "--", {"all": "all records", "ids": "typed IDs",
              "ask": "menu at run time", None: "two IDs"}.get(op.get("select"), "filter by " + str(op.get("filter_field"))))
    cfg["he"] = ops
    if any(OPS[op["type"]][0] == "p" for op in ops):
        cfg["trustees"] = ask_num("  threshold decryption: number of trustees (0 = no)", 0)

    s_type = pick("Search (a plain index is always included; add lab 8 encrypted search?):",
                  [("none", "no search menu"), ("plain", "plain index only"), ("sse", "plain + SSE"),
                   ("pkse", "plain + PKSE"), ("both", "plain + SSE + PKSE")], 5)
    if s_type != "none":
        labels = [f["label"] for f in fields if f["kind"] != "file"]
        chosen = ask_fields("  search by which field(s)", labels)
        cfg["search"] = {"types": {"plain": [], "sse": ["sse"], "pkse": ["pkse"], "both": ["sse", "pkse"]}[s_type],
                         "fields": chosen,
                         "time": yes("  also search by time range?")}

    if yes("Must the timestamp be inside a time window (deadline / voting period)?"):
        cfg["window"] = ask("  call it", "voting period")

    if yes("Role-based (RBAC) menus?", "y"):
        names = [r.strip() for r in ask("  role names, comma separated", "Patient, Doctor, Auditor").split(",") if r.strip()]
        tmp = normalize(json.loads(json.dumps(dict(cfg, roles=[]))))
        catalogue = tmp["roles"][0][1]
        labels = action_labels(tmp)
        print("  Actions:")
        for i, a in enumerate(catalogue, start=1):
            print("    %d) %s" % (i, labels[a]))
        roles = []
        for name in names:
            chosen = ask("  numbers for %s (e.g. 1,2)" % name, "1")
            picked = [catalogue[int(x) - 1] for x in re.findall(r"\d+", chosen) if 1 <= int(x) <= len(catalogue)]
            roles.append([name, picked])
        cfg["roles"] = roles

    cfg["login"] = yes("Must users LOG IN (username + password) before using a role?")
    if yes("Allow decryption only inside a time window (e.g. after the exam starts)?"):
        cfg["decrypt_window"] = ask("  call it", "exam window")
    cfg["sockets"] = yes("Also run as a socket server / client (python file.py server | client)?")
    cfg["persist"] = True if cfg["sockets"] else yes(
        "Keep keys between runs (saved to a keys file on the first run, reused later)?", "y")
    cfg["decrypted_file"] = yes("Append every decrypted record to a decrypted-records file (history)?", "y")
    cfg["access_log"] = yes("Keep an access log (who did what, when)?", "y")
    cfg["file_input"] = yes("Read inputs from a .txt file (bulk 'Import records' + --answers mode)?")
    if cfg["file_input"]:
        cfg["import_separator"] = ask("  separator between values on one line", ",")
    cfg["show_steps"] = yes("Print every calculation (keys, IV, ciphertexts, data hashed, hash, signature, "
                            "recomputed hash, encrypted totals)?", "y")
    cfg["out"] = ask("Output file", "exam_solution.py")
    return cfg


def interview_kx():
    cfg = {}
    cfg["name"] = ask("System name", "FieldTrack")
    cfg["p"] = ask_num("DH prime p", 23)
    cfg["g"] = ask_num("DH generator g", 5)
    s = ask("Sender private key (Enter = random)", 6)
    cfg["sender_private"] = int(s) if s.strip() else None
    s = ask("Receiver private key (Enter = random)", 15)
    cfg["receiver_private"] = int(s) if s.strip() else None
    cfg["cipher"] = pick("Cipher on A-Z text:", [("affine", "affine (k1 typed + validated, k2)"),
                                                 ("additive", "additive / Caesar (k = K mod 26)"),
                                                 ("multiplicative", "multiplicative (k1 typed + validated)")], 1)
    if cfg["cipher"] == "affine":
        s = ask("k2 given in the question (Enter = use K mod 26)", 2)
        cfg["k2"] = int(s) if s.strip() else None
    cfg["out"] = ask("Output file", "fieldtrack.py")
    return cfg


def generate(cfg):
    kind = cfg.get("_kind", "records")
    cfg = json.loads(json.dumps({k: v for k, v in cfg.items() if not k.startswith("_")}))    # deep copy
    return build_kx(cfg) if kind == "kx" else build_records(cfg)


def main():
    args = sys.argv[1:]
    if "--list" in args:
        for name, preset in PRESETS.items():
            print("%-13s %s" % (name, preset["_about"]))
        return

    if "--preset" in args:
        name = args[args.index("--preset") + 1]
        if name not in PRESETS:
            sys.exit("unknown preset %r; try --list" % name)
        cfg = dict(PRESETS[name])
    else:
        print("=== IS lab exam code generator ===  (Enter accepts the [default])\n")
        kind = pick("What kind of question?", [
            ("records", "record system: encrypt + hash + sign + store; verify / decrypt / tally / search per role"),
            ("kx", "key exchange + classical cipher (Diffie-Hellman -> affine ..., FieldTrack)"),
            ("preset", "one of the sample questions")], 1)
        if kind == "preset":
            name = pick("Which one?", [(n, n + " -- " + p["_about"]) for n, p in PRESETS.items()], 1)
            cfg = dict(PRESETS[name])
        elif kind == "kx":
            cfg = dict(interview_kx(), _kind="kx")
        else:
            cfg = interview_records()
        print("\nAnswers (paste into PRESETS in generate.py to reuse):")
        print(json.dumps(cfg))

    if "--out" in args:
        cfg["out"] = args[args.index("--out") + 1]
    out = cfg.get("out", "exam_solution.py")
    if not os.path.isabs(out):
        out = os.path.join(os.getcwd(), out)
    cfg["out"] = out

    code = generate(cfg)
    if os.path.exists(out) and "--force" not in args and "--preset" not in args:
        if not yes("%s exists. Overwrite?" % out):
            sys.exit("nothing written")
    with open(out, "w", encoding="utf-8") as f:
        f.write(code)
    print("\nWrote", out, "(%d lines)" % code.count("\n"))

    if "--no-test" not in args:
        print("Running its self-test ...")
        done = subprocess.run([sys.executable, out, "test"], capture_output=True, text=True, timeout=600)
        tail = (done.stdout + done.stderr).strip().splitlines()[-15:]
        print("\n".join("   | " + line for line in tail))
        print("SELF-TEST", "PASSED" if done.returncode == 0 and "SELF-TEST PASSED" in done.stdout else "FAILED")
        print("Run it:  python", os.path.relpath(out))


if __name__ == "__main__":
    main()
