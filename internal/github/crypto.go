/*
Copyright 2026 Zelyo AI
*/

package github

import (
	"crypto"
	"crypto/sha256"
	"hash"
)

// rsaSHA256Hash returns a new SHA-256 hasher for RS256 JWT signing.
func rsaSHA256Hash() hash.Hash {
	return sha256.New()
}

// rsaSHA256HashAlgo returns the crypto.Hash identifier for SHA-256.
func rsaSHA256HashAlgo() crypto.Hash {
	return crypto.SHA256
}
