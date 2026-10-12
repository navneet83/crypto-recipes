// Recipe pbe-record-pbkdf2-gcm-v1: encrypt a short record with a password.
// Standard library only (crypto/pbkdf2 is in the standard library since Go 1.24;
// on older Go use golang.org/x/crypto/pbkdf2, same signature).
//
// Key:    PBKDF2-HMAC-SHA256, 600000 iterations, random 16-byte salt, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data.
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
// This is the fallback profile of recipe R1; see RECIPES.md for the Argon2id and XAES-256-GCM profiles.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const (
	Recipe     = "pbe-record-pbkdf2-gcm-v1"
	version    = 0x01
	iterations = 600000
	saltBytes  = 16
	nonceBytes = 12
	tagBytes   = 16
)

var errNotARecord = errors.New("not a pbe-record-pbkdf2-gcm-v1 record")

func deriveKey(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iterations, 32)
}

func newGCM(password string, salt []byte) (cipher.AEAD, error) {
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext under password. salt and nonce are nil in normal use and are
// generated here; the harness passes fixed values to reproduce the vectors.
func Encrypt(password, plaintext string, salt, nonce []byte) (string, error) {
	if salt == nil {
		salt = make([]byte, saltBytes)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
	}
	if nonce == nil {
		nonce = make([]byte, nonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
	}
	if len(salt) != saltBytes || len(nonce) != nonceBytes {
		return "", errors.New("bad salt or nonce length")
	}
	gcm, err := newGCM(password, salt)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, 1+saltBytes+nonceBytes+len(plaintext)+tagBytes)
	out = append(out, version)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt opens a record. A wrong password or any modification returns an error; there is never partial output.
func Decrypt(password, text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	if len(data) < 1+saltBytes+nonceBytes+tagBytes || data[0] != version {
		return "", errNotARecord
	}
	salt := data[1 : 1+saltBytes]
	nonce := data[1+saltBytes : 1+saltBytes+nonceBytes]
	sealed := data[1+saltBytes+nonceBytes:]
	gcm, err := newGCM(password, salt)
	if err != nil {
		return "", err
	}
	opened, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", err
	}
	return string(opened), nil
}
