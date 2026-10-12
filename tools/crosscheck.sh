#!/bin/sh
# Every implementation replays the vectors; then, per recipe, every implementation emits random records
# and every implementation opens every file.
# Environment: PY (python with `cryptography`, default .venv/bin/python), JAVA (default java), DOTNET (default dotnet).
set -eu
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
JAVA=${JAVA:-java}
DOTNET=${DOTNET:-dotnet}
T=$(mktemp -d)
"$DOTNET" build -c Release impl/csharp -o "$T/csharp" > "$T/csharp-build.log" 2>&1 || { cat "$T/csharp-build.log"; exit 1; }
(cd impl/swift && swift build -c release > "$T/swift-build.log" 2>&1) || { cat "$T/swift-build.log"; exit 1; }
run() {
    lang=$1; shift
    case $lang in
        typescript) node impl/typescript/harness.mjs "$@" ;;
        python) "$PY" impl/python/harness.py "$@" ;;
        swift) RECIPES_ROOT=. impl/swift/.build/release/harness "$@" ;;
        go) (cd impl/go && go run . "$@") ;;
        java) "$JAVA" -Drecipes.root=. impl/java/Harness.java "$@" ;;
        csharp) RECIPES_ROOT=. "$DOTNET" "$T/csharp/harness.dll" "$@" ;;
    esac
}
LANGS="typescript python swift go java csharp"
RECIPES=$(ls vectors)
for l in $LANGS; do run "$l"; done
for r in $RECIPES; do
    for l in $LANGS; do run "$l" "$r" --emit 30 "$T/$r-$l.json"; done
    for f in $LANGS; do for l in $LANGS; do run "$l" "$r" --consume "$T/$r-$f.json"; done; done
done
rm -rf "$T"
echo "crosscheck: all pairs OK"
