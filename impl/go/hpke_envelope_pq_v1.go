// Recipe hpke-envelope-pq-v1: encrypt a short record to a recipient's public key, post-quantum hybrid.
// Standard library only (crypto/hpke, Go 1.26+).
//
// Suite:  HPKE base mode with the KEM MLKEM768-X25519 (X-Wing, KEM id 0x647a, draft-ietf-hpke-pq), HKDF-SHA256,
//
//	AES-256-GCM, single-shot, no additional data. A record stays confidential unless both ML-KEM-768 and X25519 fall.
//
// Info:   "crypto-recipes/hpke-envelope-pq-v1".
// Keys:   recipient private key is the 32-byte X-Wing seed; public key is ML-KEM-768 (1184) || X25519 (32).
// Output: Base64 of  version (1 byte, 0x01) || enc (1120) || ciphertext || tag (16).
package main

import (
	"crypto/hpke"
	"encoding/base64"
	"errors"
)

const (
	HpkePqRecipe   = "hpke-envelope-pq-v1"
	hpkePqInfo     = "crypto-recipes/hpke-envelope-pq-v1"
	hpkePqEncBytes = 1120
)

var hpkePqKEM = hpke.MLKEM768X25519()

func HpkePqPublicKey(seed []byte) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("private key must be the 32-byte X-Wing seed")
	}
	k, err := hpkePqKEM.NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func HpkePqEncrypt(public []byte, plaintext string) (string, error) {
	pk, err := hpkePqKEM.NewPublicKey(public)
	if err != nil {
		return "", err
	}
	sealed, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hpkePqInfo), []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append([]byte{hpkeVersion}, sealed...)), nil
}

// HpkePqDecrypt opens a record. A wrong key or any modification returns an error; there is never partial output.
func HpkePqDecrypt(seed []byte, text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	if len(data) < 1+hpkePqEncBytes+hpkeTagBytes || data[0] != hpkeVersion {
		return "", errors.New("not an hpke-envelope-pq-v1 record")
	}
	if len(seed) != 32 {
		return "", errors.New("private key must be the 32-byte X-Wing seed")
	}
	k, err := hpkePqKEM.NewPrivateKey(seed)
	if err != nil {
		return "", err
	}
	opened, err := hpke.Open(k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hpkePqInfo), data[1:])
	if err != nil {
		return "", err
	}
	return string(opened), nil
}
