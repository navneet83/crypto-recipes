// Recipe aead-record-v1: encrypt a short record with a 32-byte key you already have.
// Standard library only. Cipher is XAES-256-GCM (https://c2sp.org/XAES-256-GCM): a 24-byte random nonce,
// from which a per-message AES-256-GCM key is derived with one block of AES-CMAC, so random nonces are
// safe for any number of messages under one key.
//
// Key:    32 bytes, from a KMS, a key store or a KDF; never a password (see pbe-record-v1).
// Cipher: XAES-256-GCM, random 24-byte nonce, 16-byte tag, optional additional data (not stored).
// Output: Base64 of  version (1 byte, 0x01) || nonce (24) || ciphertext || tag (16).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

const (
	AeadRecipe     = "aead-record-v1"
	aeadVersion    = 0x01
	aeadKeyBytes   = 32
	aeadNonceBytes = 24
	aeadTagBytes   = 16
)

var errNotAnAeadRecord = errors.New("not an aead-record-v1 record")

// xaesGCM derives the per-message AES-256-GCM key (steps 1-5 of the specification) and returns the AEAD
// together with the 12-byte GCM nonce (step 6).
func xaesGCM(key, nonce []byte) (cipher.AEAD, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	var l, k1 [16]byte
	block.Encrypt(l[:], l[:])
	for i := range k1 {
		k1[i] = l[i] << 1
		if i < 15 {
			k1[i] |= l[i+1] >> 7
		}
	}
	if l[0]&0x80 != 0 {
		k1[15] ^= 0x87
	}
	kx := make([]byte, 32)
	for i, counter := range []byte{1, 2} {
		m := [16]byte{0x00, counter, 0x58, 0x00}
		copy(m[4:], nonce[:12])
		for j := range m {
			m[j] ^= k1[j]
		}
		block.Encrypt(kx[16*i:], m[:])
	}
	inner, err := aes.NewCipher(kx)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(inner)
	return gcm, nonce[12:], err
}

// AeadEncrypt seals plaintext under key. nonce is nil in normal use and generated here; the harness
// passes a fixed value to reproduce the vectors.
func AeadEncrypt(key []byte, plaintext, aad string, nonce []byte) (string, error) {
	if len(key) != aeadKeyBytes {
		return "", errors.New("key must be 32 bytes")
	}
	if nonce == nil {
		nonce = make([]byte, aeadNonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
	}
	if len(nonce) != aeadNonceBytes {
		return "", errors.New("bad nonce length")
	}
	gcm, nx, err := xaesGCM(key, nonce)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, 1+aeadNonceBytes+len(plaintext)+aeadTagBytes)
	out = append(out, aeadVersion)
	out = append(out, nonce...)
	out = gcm.Seal(out, nx, []byte(plaintext), []byte(aad))
	return base64.StdEncoding.EncodeToString(out), nil
}

// AeadDecrypt opens a record. A wrong key, wrong additional data or any modification returns an error;
// there is never partial output.
func AeadDecrypt(key []byte, text, aad string) (string, error) {
	if len(key) != aeadKeyBytes {
		return "", errors.New("key must be 32 bytes")
	}
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	if len(data) < 1+aeadNonceBytes+aeadTagBytes || data[0] != aeadVersion {
		return "", errNotAnAeadRecord
	}
	gcm, nx, err := xaesGCM(key, data[1:1+aeadNonceBytes])
	if err != nil {
		return "", err
	}
	opened, err := gcm.Open(nil, nx, data[1+aeadNonceBytes:], []byte(aad))
	if err != nil {
		return "", err
	}
	return string(opened), nil
}
