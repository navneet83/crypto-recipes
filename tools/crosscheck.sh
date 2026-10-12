#!/bin/sh
# Every implementation emits random records; every implementation opens every file.
set -eu
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
T=$(mktemp -d)
node impl/typescript/harness.mjs --emit 30 "$T/typescript.json"
"$PY" impl/python/harness.py --emit 30 "$T/python.json"
swift impl/swift/pbe_record_pbkdf2_gcm_v1.swift --emit 30 "$T/swift.json"
for f in "$T"/*.json; do
    node impl/typescript/harness.mjs --consume "$f"
    "$PY" impl/python/harness.py --consume "$f"
    swift impl/swift/pbe_record_pbkdf2_gcm_v1.swift --consume "$f"
done
rm -rf "$T"
echo "crosscheck: all pairs OK"
