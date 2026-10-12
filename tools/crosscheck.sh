#!/bin/sh
# Every implementation replays the vectors for the recipes it supports; then, per recipe, every supporting
# implementation emits random records and every supporting implementation opens every file.
# Environment: PY (python with `cryptography`, default .venv/bin/python), JAVA (default java), DOTNET (default dotnet),
# LANGS (default: all six) to restrict the languages, for example on a runner without Swift.
set -eu
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
JAVA=${JAVA:-java}
DOTNET=${DOTNET:-dotnet}
LANGS=${LANGS:-typescript python swift go java csharp}
T=$(mktemp -d)
case " $LANGS " in *" csharp "*) "$DOTNET" build -c Release impl/csharp -o "$T/csharp" > "$T/csharp-build.log" 2>&1 || { cat "$T/csharp-build.log"; exit 1; };; esac
case " $LANGS " in *" swift "*) (cd impl/swift && swift build -c release > "$T/swift-build.log" 2>&1) || { cat "$T/swift-build.log"; exit 1; };; esac
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
supports() { run "$1" --list | grep -qx "$2"; }
for l in $LANGS; do run "$l"; done
pairs=0
for r in $(ls vectors); do
    langs=""
    for l in $LANGS; do supports "$l" "$r" && langs="$langs $l"; done
    echo "$r:$langs"
    for l in $langs; do run "$l" "$r" --emit 30 "$T/$r-$l.json"; done
    for f in $langs; do for l in $langs; do run "$l" "$r" --consume "$T/$r-$f.json"; pairs=$((pairs + 1)); done; done
done
rm -rf "$T"
echo "crosscheck: all $pairs pairs OK"
