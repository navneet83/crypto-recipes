// Runs the recipes over their vectors, emits random records, or consumes another implementation's records.
//
//	go run .                            replay cases.json and negative.json for every recipe
//	go run . <recipe> --emit N FILE     write N random records for the cross-language check
//	go run . <recipe> --consume FILE    open records produced by another implementation
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type fields = map[string]string

type recipe struct {
	replay  func(c fields) (string, error)
	open    func(c fields, field string) (string, error)
	emit    func(i int) (fields, error)
	consume func(it fields) (string, error)
}

func plaintextFor(i int) string {
	if i%3 == 0 {
		return ""
	}
	return fmt.Sprintf("record %d %s ünïcödé ✓", i, strings.Repeat("x", i*7))
}

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func randomHex(n int) string { b := make([]byte, n); rand.Read(b); return hex.EncodeToString(b) }

var recipes = map[string]recipe{
	Recipe: {
		replay: func(c fields) (string, error) {
			return Encrypt(c["password"], c["plaintext"], unhex(c["salt_hex"]), unhex(c["nonce_hex"]))
		},
		open: func(c fields, field string) (string, error) { return Decrypt(c["password"], c[field]) },
		emit: func(i int) (fields, error) {
			password := fmt.Sprintf("pw-%d-%s", i, randomHex(16))
			rec, err := Encrypt(password, plaintextFor(i), nil, nil)
			return fields{"password": password, "plaintext": plaintextFor(i), "record": rec}, err
		},
		consume: func(it fields) (string, error) { return Decrypt(it["password"], it["record"]) },
	},
	AeadRecipe: {
		replay: func(c fields) (string, error) {
			return AeadEncrypt(unhex(c["key_hex"]), c["plaintext"], c["aad"], unhex(c["nonce_hex"]))
		},
		open: func(c fields, field string) (string, error) {
			return AeadDecrypt(unhex(c["key_hex"]), c[field], c["aad"])
		},
		emit: func(i int) (fields, error) {
			key, aad := randomHex(32), ""
			if i%2 == 0 {
				aad = fmt.Sprintf("aad-%d", i)
			}
			rec, err := AeadEncrypt(unhex(key), plaintextFor(i), aad, nil)
			return fields{"key_hex": key, "aad": aad, "plaintext": plaintextFor(i), "record": rec}, err
		},
		consume: func(it fields) (string, error) { return AeadDecrypt(unhex(it["key_hex"]), it["record"], it["aad"]) },
	},
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		fail("%v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		fail("%s: %v", path, err)
	}
}

type caseFile struct {
	Cases []fields `json:"cases"`
}

type batch struct {
	Recipe   string   `json:"recipe"`
	Producer string   `json:"producer"`
	Items    []fields `json:"items"`
}

func replay(name string, r recipe) {
	_, here, _, _ := runtime.Caller(0)
	vdir := filepath.Join(filepath.Dir(here), "..", "..", "vectors", name)
	var cases, negative caseFile
	readJSON(filepath.Join(vdir, "cases.json"), &cases)
	for _, c := range cases.Cases {
		if produced, err := r.replay(c); err != nil || produced != c["output_base64"] {
			fail("%s case %s: produced %s (%v)", name, c["id"], produced, err)
		}
		if got, err := r.open(c, "output_base64"); err != nil || got != c["plaintext"] {
			fail("%s case %s: decrypt mismatch (%v)", name, c["id"], err)
		}
	}
	readJSON(filepath.Join(vdir, "negative.json"), &negative)
	for _, c := range negative.Cases {
		if got, err := r.open(c, "input_base64"); err == nil {
			fail("%s negative case %s (%s) returned plaintext: %q", name, c["id"], c["note"], got)
		}
	}
	fmt.Printf("go: %d cases and %d negative cases OK for %s\n", len(cases.Cases), len(negative.Cases), name)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		for _, name := range []string{Recipe, AeadRecipe} {
			replay(name, recipes[name])
		}
		return
	}
	name := args[0]
	r, ok := recipes[name]
	if !ok {
		fail("unknown recipe %s", name)
	}
	switch {
	case len(args) == 4 && args[1] == "--emit":
		n, _ := strconv.Atoi(args[2])
		items := []fields{}
		for i := 0; i < n; i++ {
			it, err := r.emit(i)
			if err != nil {
				fail("%v", err)
			}
			items = append(items, it)
		}
		b, _ := json.MarshalIndent(batch{name, "go", items}, "", " ")
		if err := os.WriteFile(args[3], b, 0o644); err != nil {
			fail("%v", err)
		}
		fmt.Printf("go: emitted %d records to %s for %s\n", n, args[3], name)
	case len(args) == 3 && args[1] == "--consume":
		var b batch
		readJSON(args[2], &b)
		if b.Recipe != name {
			fail("recipe mismatch")
		}
		for _, it := range b.Items {
			if got, err := r.consume(it); err != nil || got != it["plaintext"] {
				fail("go could not open a %s record from %s: %v", name, b.Producer, err)
			}
		}
		fmt.Printf("go: opened %d %s records from %s\n", len(b.Items), name, b.Producer)
	default:
		fail("usage: harness [<recipe> --emit N FILE | <recipe> --consume FILE]")
	}
}
