// Recipe pbe-record-v1: encrypt a short record with a password.
// Standard library plus golang.org/x/crypto/argon2 (the Go standard library has no Argon2).
//
// Key:    Argon2id, 64 MiB memory, 3 passes, 1 lane, random 16-byte salt, 32-byte output, over the UTF-8 bytes of the password.
// Cipher: AES-256-GCM, random 12-byte nonce, 16-byte tag, no additional data. The salt is fresh per record, so the
//
//	derived key is used once and a 12-byte random nonce is safe; the extended-nonce cipher of aead-record-v1 is not needed.
//
// Output: Base64 of  version (1 byte, 0x01) || salt (16) || nonce (12) || ciphertext || tag (16).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2Recipe     = "pbe-record-v1"
	argon2Version    = 0x01
	argon2MemoryKiB  = 64 * 1024
	argon2Passes     = 3
	argon2Lanes      = 1
	argon2SaltBytes  = 16
	argon2NonceBytes = 12
	argon2TagBytes   = 16
)

func argon2GCM(password string, salt []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(argon2.IDKey([]byte(password), salt, argon2Passes, argon2MemoryKiB, argon2Lanes, 32))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Argon2Encrypt seals plaintext under password. salt and nonce are nil in normal use and are generated here.
func Argon2Encrypt(password, plaintext string, salt, nonce []byte) (string, error) {
	if salt == nil {
		salt = make([]byte, argon2SaltBytes)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
	}
	if nonce == nil {
		nonce = make([]byte, argon2NonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
	}
	if len(salt) != argon2SaltBytes || len(nonce) != argon2NonceBytes {
		return "", errors.New("bad salt or nonce length")
	}
	gcm, err := argon2GCM(password, salt)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, 1+argon2SaltBytes+argon2NonceBytes+len(plaintext)+argon2TagBytes)
	out = append(out, argon2Version)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Argon2Decrypt opens a record. A wrong password or any modification returns an error; there is never partial output.
func Argon2Decrypt(password, text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	if len(data) < 1+argon2SaltBytes+argon2NonceBytes+argon2TagBytes || data[0] != argon2Version {
		return "", errors.New("not a pbe-record-v1 record")
	}
	salt := data[1 : 1+argon2SaltBytes]
	nonce := data[1+argon2SaltBytes : 1+argon2SaltBytes+argon2NonceBytes]
	gcm, err := argon2GCM(password, salt)
	if err != nil {
		return "", err
	}
	opened, err := gcm.Open(nil, nonce, data[1+argon2SaltBytes+argon2NonceBytes:], nil)
	if err != nil {
		return "", err
	}
	return string(opened), nil
}
