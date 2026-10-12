// Recipe sign-detached-v1: sign a message and verify the signature.
// Standard library only.
//
// Keys:      Ed25519 (RFC 8032). Private key is the 32-byte seed, public key is the 32-byte point, both Base64 when
//
//	transported. Go's 64-byte "private key" is seed || public; the seed is what to store.
//
// Input:     "crypto-recipes/sign-detached-v1" || 0x00 || message. The prefix stops a signature made for this recipe
//
//	from meaning anything in another protocol that signs raw bytes with the same key, and the other way round.
//
// Signature: the 64 raw Ed25519 bytes, Base64 (standard alphabet, with padding). The public key and the message
//
//	travel separately, which is what "detached" means.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

const (
	SignRecipe = "sign-detached-v1"
	signDomain = "crypto-recipes/sign-detached-v1\x00"
)

var errInvalidSignature = errors.New("invalid signature")

func SignPublicKey(seed []byte) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

func Sign(seed []byte, message string) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", errors.New("seed must be 32 bytes")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(signDomain+message))), nil
}

// Verify returns nil for a valid signature and an error for anything else.
func Verify(public []byte, message, signature string) error {
	if len(public) != ed25519.PublicKeySize {
		return errors.New("public key must be 32 bytes")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(public), []byte(signDomain+message), sig) {
		return errInvalidSignature
	}
	return nil
}
