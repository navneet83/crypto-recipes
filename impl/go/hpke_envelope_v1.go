// Recipe hpke-envelope-v1: encrypt a short record to a recipient's public key.
// Standard library only (crypto/hpke, Go 1.26+).
//
// Suite:  HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single-shot, no additional data.
// Info:   "crypto-recipes/hpke-envelope-v1", which binds every record to this recipe.
// Keys:   recipient private key is the 32-byte X25519 scalar, public key the 32-byte point.
// Output: Base64 of  version (1 byte, 0x01) || enc (32) || ciphertext || tag (16).
package main

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
)

const (
	HpkeRecipe   = "hpke-envelope-v1"
	hpkeVersion  = 0x01
	hpkeInfo     = "crypto-recipes/hpke-envelope-v1"
	hpkeEncBytes = 32
	hpkeTagBytes = 16
)

var hpkeKEM = hpke.DHKEM(ecdh.X25519())

func HpkePublicKey(private []byte) ([]byte, error) {
	k, err := hpkeKEM.NewPrivateKey(private)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func HpkeEncrypt(public []byte, plaintext string) (string, error) {
	pk, err := hpkeKEM.NewPublicKey(public)
	if err != nil {
		return "", err
	}
	sealed, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hpkeInfo), []byte(plaintext)) // enc || ct || tag
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(append([]byte{hpkeVersion}, sealed...)), nil
}

// HpkeDecrypt opens a record. A wrong key or any modification returns an error; there is never partial output.
func HpkeDecrypt(private []byte, text string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	if len(data) < 1+hpkeEncBytes+hpkeTagBytes || data[0] != hpkeVersion {
		return "", errors.New("not an hpke-envelope-v1 record")
	}
	k, err := hpkeKEM.NewPrivateKey(private)
	if err != nil {
		return "", err
	}
	opened, err := hpke.Open(k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(hpkeInfo), data[1:])
	if err != nil {
		return "", err
	}
	return string(opened), nil
}
