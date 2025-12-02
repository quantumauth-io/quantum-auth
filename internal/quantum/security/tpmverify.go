package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// VerifyTPMSignature verifies an ECDSA P-256 signature produced by the TPM.
//
// pubKeyB64: base64 of uncompressed EC point: 0x04 || X(32) || Y(32)
// msg:       the raw message bytes (same JSON blob as PQ)
// sigB64:    base64 of R(32) || S(32) big-endian
func VerifyTPMSignature(pubKeyB64 string, msg []byte, sigB64 string) bool {
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false
	}

	pubKey, err := parseUncompressedP256(pubBytes)
	if err != nil {
		return false
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	if len(sigBytes) != 64 { // 32 bytes R + 32 bytes S
		return false
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	digest := sha256.Sum256(msg)

	return ecdsa.Verify(pubKey, digest[:], r, s)
}

func parseUncompressedP256(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 1+32+32 || b[0] != 0x04 {
		return nil, errors.New("invalid uncompressed P-256 key")
	}
	x := new(big.Int).SetBytes(b[1 : 1+32])
	y := new(big.Int).SetBytes(b[1+32:])

	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("point not on P-256 curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
