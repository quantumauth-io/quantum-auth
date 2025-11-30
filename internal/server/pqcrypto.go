package server

import (
	"encoding/base64"
	"log"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// Choose a post-quantum signature scheme.
// ML-DSA-65 ≈ Dilithium3-level security.
var pqScheme sign.Scheme

func init() {
	pqScheme = schemes.ByName("ML-DSA-65")
	if pqScheme == nil {
		log.Fatal("PQ scheme ML-DSA-65 not found in CIRCL")
	}
}

// verifyPQSignature verifies a base64-encoded ML-DSA signature
// against a base64-encoded public key and message bytes.
func verifyPQSignature(pubKeyB64 string, msg []byte, sigB64 string) bool {
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false
	}

	pk, err := pqScheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return false
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}

	return pqScheme.Verify(pk, msg, sigBytes, nil)
}
