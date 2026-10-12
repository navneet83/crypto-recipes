#!/bin/sh
# Every implementation emits random records; every implementation opens every file.
# Environment: PY (python with `cryptography`, default .venv/bin/python), JAVA (default java), DOTNET (default dotnet).
set -eu
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
JAVA=${JAVA:-java}
DOTNET=${DOTNET:-dotnet}
T=$(mktemp -d)
"$DOTNET" build -c Release impl/csharp -o "$T/csharp" > "$T/csharp-build.log" 2>&1 || { cat "$T/csharp-build.log"; exit 1; }
run() {
    lang=$1; shift
    case $lang in
        typescript) node impl/typescript/harness.mjs "$@" ;;
        python) "$PY" impl/python/harness.py "$@" ;;
        swift) swift impl/swift/pbe_record_pbkdf2_gcm_v1.swift "$@" ;;
        go) (cd impl/go && go run . "$@") ;;
        java) "$JAVA" -Drecipes.root=. impl/java/PbeRecordPbkdf2GcmV1.java "$@" ;;
        csharp) RECIPES_ROOT=. "$DOTNET" "$T/csharp/harness.dll" "$@" ;;
    esac
}
LANGS="typescript python swift go java csharp"
for l in $LANGS; do run "$l"; done
for l in $LANGS; do run "$l" --emit 30 "$T/$l.json"; done
for f in $LANGS; do for l in $LANGS; do run "$l" --consume "$T/$f.json"; done; done
rm -rf "$T"
echo "crosscheck: all pairs OK"
