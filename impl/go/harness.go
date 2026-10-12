// Runs the recipe over its vectors, emits random records, or consumes another implementation's records.
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

type vectorCase struct {
	ID, Password, SaltHex, NonceHex, Plaintext, OutputBase64 string
}
type negativeCase struct {
	ID, Password, InputBase64, Note string
}
type item struct {
	Password  string `json:"password"`
	Plaintext string `json:"plaintext"`
	Record    string `json:"record"`
}
type batch struct {
	Recipe   string `json:"recipe"`
	Producer string `json:"producer"`
	Items    []item `json:"items"`
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

func main() {
	_, here, _, _ := runtime.Caller(0)
	vdir := filepath.Join(filepath.Dir(here), "..", "..", "vectors", Recipe)
	args := os.Args[1:]
	switch {
	case len(args) == 3 && args[0] == "--emit":
		n, _ := strconv.Atoi(args[1])
		var items []item
		for i := 0; i < n; i++ {
			r := make([]byte, 16)
			rand.Read(r)
			password := fmt.Sprintf("pw-%d-%x", i, r)
			plaintext := ""
			if i%3 != 0 {
				plaintext = fmt.Sprintf("record %d %s ünïcödé ✓", i, strings.Repeat("x", i*7))
			}
			rec, err := Encrypt(password, plaintext, nil, nil)
			if err != nil {
				fail("%v", err)
			}
			items = append(items, item{password, plaintext, rec})
		}
		b, _ := json.MarshalIndent(batch{Recipe, "go", items}, "", " ")
		if err := os.WriteFile(args[2], b, 0o644); err != nil {
			fail("%v", err)
		}
		fmt.Printf("go: emitted %d records to %s\n", n, args[2])
	case len(args) == 2 && args[0] == "--consume":
		var b batch
		readJSON(args[1], &b)
		if b.Recipe != Recipe {
			fail("recipe mismatch")
		}
		for _, it := range b.Items {
			if got, err := Decrypt(it.Password, it.Record); err != nil || got != it.Plaintext {
				fail("go could not open a record from %s: %v", b.Producer, err)
			}
		}
		fmt.Printf("go: opened %d records from %s\n", len(b.Items), b.Producer)
	default:
		var cases struct {
			Cases []map[string]string `json:"cases"`
		}
		readJSON(filepath.Join(vdir, "cases.json"), &cases)
		for _, c := range cases.Cases {
			salt, _ := hex.DecodeString(c["salt_hex"])
			nonce, _ := hex.DecodeString(c["nonce_hex"])
			produced, err := Encrypt(c["password"], c["plaintext"], salt, nonce)
			if err != nil || produced != c["output_base64"] {
				fail("case %s: produced %s (%v)", c["id"], produced, err)
			}
			if got, err := Decrypt(c["password"], c["output_base64"]); err != nil || got != c["plaintext"] {
				fail("case %s: decrypt mismatch (%v)", c["id"], err)
			}
		}
		var negative struct {
			Cases []map[string]string `json:"cases"`
		}
		readJSON(filepath.Join(vdir, "negative.json"), &negative)
		for _, c := range negative.Cases {
			if got, err := Decrypt(c["password"], c["input_base64"]); err == nil {
				fail("negative case %s (%s) returned plaintext: %q", c["id"], c["note"], got)
			}
		}
		fmt.Printf("go: %d cases and %d negative cases OK for %s\n", len(cases.Cases), len(negative.Cases), Recipe)
	}
}
