// Recipe sign-detached-pq-v1: sign a message and verify the signature, post-quantum.
// Standard library only (crypto/mldsa, Go 1.27+).
//
// Keys:      ML-DSA-65 (FIPS 204). Private key is the 32-byte seed; public key is the 1952-byte encoding. Both Base64
//
//	when transported.
//
// Input:     "crypto-recipes/sign-detached-pq-v1" || 0x00 || message, with an empty FIPS 204 context string.
// Signature: the 3309 raw ML-DSA-65 bytes, Base64. Signing is randomized: two signatures of one message differ.
package main

import (
	"crypto/mldsa"
	"encoding/base64"
	"errors"
)

const (
	SignPqRecipe        = "sign-detached-pq-v1"
	signPqDomain        = "crypto-recipes/sign-detached-pq-v1\x00"
	signPqSeedBytes     = 32
	signPqPublicBytes   = 1952
	signPqSignatureSize = 3309
)

func SignPqPublicKey(seed []byte) ([]byte, error) {
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func SignPq(seed []byte, message string) (string, error) {
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return "", err
	}
	sig, err := k.Sign(nil, []byte(signPqDomain+message), &mldsa.Options{})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyPq returns nil for a valid signature and an error for anything else.
func VerifyPq(public []byte, message, signature string) error {
	if len(public) != signPqPublicBytes {
		return errors.New("public key must be 1952 bytes")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if len(sig) != signPqSignatureSize {
		return errInvalidSignature
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), public)
	if err != nil {
		return err
	}
	return mldsa.Verify(pk, []byte(signPqDomain+message), sig, &mldsa.Options{})
}
