"""Runs the recipes over their vectors, emits random records, or consumes another implementation's records.

    harness.py                         replay cases.json and negative.json for every recipe
    harness.py --list                  print the recipes this implementation supports, one per line
    harness.py <recipe> --emit N FILE  write N random records for the cross-language check
    harness.py <recipe> --consume FILE open records produced by another implementation
"""
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(__file__))
import aead_record_v1  # noqa: E402
import hpke_envelope_pq_v1  # noqa: E402
import hpke_envelope_v1  # noqa: E402
import pbe_record_pbkdf2_gcm_v1  # noqa: E402
import pbe_record_v1  # noqa: E402
import sign_detached_pq_v1  # noqa: E402
import sign_detached_v1  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def _plaintext(i):
    return "" if i % 3 == 0 else f"record {i} {'x' * (i * 7)} ünïcödé ✓"


class Pbe:
    r = pbe_record_pbkdf2_gcm_v1
    def replay(self, c): return self.r.encrypt(c["password"], c["plaintext"], bytes.fromhex(c["salt_hex"]), bytes.fromhex(c["nonce_hex"]))
    def open(self, c, field): return self.r.decrypt(c["password"], c[field])
    def emit(self, i):
        pw = f"pw-{i}-{uuid.uuid4()}"
        return {"password": pw, "plaintext": _plaintext(i), "record": self.r.encrypt(pw, _plaintext(i))}
    def consume(self, it): return self.r.decrypt(it["password"], it["record"])


class Aead:
    r = aead_record_v1
    def replay(self, c): return self.r.encrypt(bytes.fromhex(c["key_hex"]), c["plaintext"], c["aad"], bytes.fromhex(c["nonce_hex"]))
    def open(self, c, field): return self.r.decrypt(bytes.fromhex(c["key_hex"]), c[field], c["aad"])
    def emit(self, i):
        key = os.urandom(32); aad = "" if i % 2 else f"aad-{i}"
        return {"key_hex": key.hex(), "aad": aad, "plaintext": _plaintext(i), "record": self.r.encrypt(key, _plaintext(i), aad)}
    def consume(self, it): return self.r.decrypt(bytes.fromhex(it["key_hex"]), it["record"], it["aad"])


class Argon2(Pbe):
    r = pbe_record_v1


class Sign:
    r = sign_detached_v1
    deterministic = True
    def replay(self, c):
        assert self.r.public_key(bytes.fromhex(c["seed_hex"])).hex() == c["public_hex"], f"{c['id']}: public key mismatch"
        return self.r.sign(bytes.fromhex(c["seed_hex"]), c["message"])
    def open(self, c, field):
        self.r.verify(bytes.fromhex(c["public_hex"]), c["message"], c[field])
        return c["message"]
    def emit(self, i):
        seed = os.urandom(32)
        return {"seed_hex": seed.hex(), "public_hex": self.r.public_key(seed).hex(), "message": _plaintext(i), "record": self.r.sign(seed, _plaintext(i))}
    def consume(self, it):
        assert self.r.public_key(bytes.fromhex(it["seed_hex"])).hex() == it["public_hex"], "public key mismatch"
        self.r.verify(bytes.fromhex(it["public_hex"]), it["message"], it["record"])
        return it["message"]


class SignPq(Sign):
    r = sign_detached_pq_v1
    deterministic = False  # ML-DSA signing is randomized; own output is checked by verification.


class Hpke:
    r = hpke_envelope_v1
    deterministic = False  # fresh ephemeral key per record; own output is checked by opening it.
    def _check(self, c):
        assert self.r.public_key(bytes.fromhex(c["private_hex"])).hex() == c["public_hex"], "public key mismatch"
    def replay(self, c):
        self._check(c)
        return self.r.encrypt(bytes.fromhex(c["public_hex"]), c["plaintext"])
    def open(self, c, field): return self.r.decrypt(bytes.fromhex(c["private_hex"]), c[field])
    def emit(self, i):
        priv = os.urandom(32); pub = self.r.public_key(priv)
        return {"private_hex": priv.hex(), "public_hex": pub.hex(), "plaintext": _plaintext(i), "record": self.r.encrypt(pub, _plaintext(i))}
    def consume(self, it):
        self._check(it)
        return self.r.decrypt(bytes.fromhex(it["private_hex"]), it["record"])


class HpkePq(Hpke):
    r = hpke_envelope_pq_v1
    def emit(self, i):
        seed = os.urandom(32); pub = self.r.public_key(seed)
        return {"private_hex": seed.hex(), "public_hex": pub.hex(), "plaintext": _plaintext(i), "record": self.r.encrypt(pub, _plaintext(i))}


RECIPES = {Pbe.r.RECIPE: Pbe(), Hpke.r.RECIPE: Hpke(), HpkePq.r.RECIPE: HpkePq(), Aead.r.RECIPE: Aead(), Argon2.r.RECIPE: Argon2(), Sign.r.RECIPE: Sign(), SignPq.r.RECIPE: SignPq()}


def expected(c):
    """Encryption vectors carry the plaintext, signature vectors the message."""
    return c["message"] if "message" in c else c["plaintext"]


def replay(name, impl):
    vdir = os.path.join(ROOT, "vectors", name)
    with open(os.path.join(vdir, "cases.json")) as f:
        cases = json.load(f)["cases"]
    for c in cases:
        produced = impl.replay(c)
        field = next(f for f in ("signature_base64", "record_base64", "output_base64") if f in c)
        if getattr(impl, "deterministic", True):
            assert produced == c[field], f"{name} case {c['id']}: produced {produced}"
        else:
            assert impl.open({**c, field: produced}, field) == expected(c), f"{name} case {c['id']}: own output does not verify"
        assert impl.open(c, field) == expected(c), f"{name} case {c['id']}: open mismatch"
    with open(os.path.join(vdir, "negative.json")) as f:
        negative = json.load(f)["cases"]
    for c in negative:
        try:
            opened = impl.open(c, "input_base64")
        except Exception:
            continue
        raise AssertionError(f"{name} negative case {c['id']} ({c['note']}) returned plaintext: {opened!r}")
    print(f"python: {len(cases)} cases and {len(negative)} negative cases OK for {name}")


def main(argv):
    if argv == ["--list"]:
        print("\n".join(RECIPES))
        return
    if not argv:
        for name, impl in RECIPES.items():
            replay(name, impl)
        return
    name, impl = argv[0], RECIPES[argv[0]]
    if argv[1] == "--emit":
        n = int(argv[2])
        with open(argv[3], "w") as f:
            json.dump({"recipe": name, "producer": "python", "items": [impl.emit(i) for i in range(n)]}, f, indent=1)
        print(f"python: emitted {n} records to {argv[3]} for {name}")
    elif argv[1] == "--consume":
        with open(argv[2]) as f:
            data = json.load(f)
        assert data["recipe"] == name, "recipe mismatch"
        for it in data["items"]:
            assert impl.consume(it) == expected(it), f"python could not open a {name} record from {data['producer']}"
        print(f"python: opened {len(data['items'])} {name} records from {data['producer']}")


if __name__ == "__main__":
    main(sys.argv[1:])
