"""Runs a recipe over its vectors, emits random records, or consumes another implementation's records."""
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(__file__))
import pbe_record_pbkdf2_gcm_v1 as r  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
VDIR = os.path.join(ROOT, "vectors", r.RECIPE)


def main(argv):
    if argv[:1] == ["--emit"]:
        n = int(argv[1]); items = []
        for i in range(n):
            password = f"pw-{i}-{uuid.uuid4()}"
            plaintext = "" if i % 3 == 0 else f"record {i} {'x' * (i * 7)} ünïcödé ✓"
            items.append({"password": password, "plaintext": plaintext, "record": r.encrypt(password, plaintext)})
        with open(argv[2], "w") as f:
            json.dump({"recipe": r.RECIPE, "producer": "python", "items": items}, f, indent=1)
        print(f"python: emitted {n} records to {argv[2]}")
    elif argv[:1] == ["--consume"]:
        with open(argv[1]) as f:
            data = json.load(f)
        assert data["recipe"] == r.RECIPE, "recipe mismatch"
        for it in data["items"]:
            assert r.decrypt(it["password"], it["record"]) == it["plaintext"], f"python could not open a record from {data['producer']}"
        print(f"python: opened {len(data['items'])} records from {data['producer']}")
    else:
        with open(os.path.join(VDIR, "cases.json")) as f:
            cases = json.load(f)["cases"]
        for c in cases:
            produced = r.encrypt(c["password"], c["plaintext"], bytes.fromhex(c["salt_hex"]), bytes.fromhex(c["nonce_hex"]))
            assert produced == c["output_base64"], f"case {c['id']}: produced {produced}"
            assert r.decrypt(c["password"], c["output_base64"]) == c["plaintext"], f"case {c['id']}: decrypt mismatch"
        with open(os.path.join(VDIR, "negative.json")) as f:
            negative = json.load(f)["cases"]
        for c in negative:
            try:
                opened = r.decrypt(c["password"], c["input_base64"])
            except Exception:
                continue
            raise AssertionError(f"negative case {c['id']} ({c['note']}) returned plaintext: {opened!r}")
        print(f"python: {len(cases)} cases and {len(negative)} negative cases OK for {r.RECIPE}")


if __name__ == "__main__":
    main(sys.argv[1:])
