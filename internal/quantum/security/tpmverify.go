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

func VerifyTPMWithDiagnostics(pubKeyB64 string, msg []byte, sigB64 string) (ok bool, mode string) {
	// parse pubkey + sig exactly the same way as VerifyTPMSignature
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return false, "pub_b64_decode_failed"
	}
	pubKey, err := parseUncompressedP256(pubBytes)
	if err != nil {
		return false, "pub_parse_failed"
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, "sig_b64_decode_failed"
	}
	if len(sigBytes) != 64 {
		return false, "sig_len_not_64"
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// A) what you currently do: digest = sha256(msg)
	d1 := sha256.Sum256(msg)
	if ecdsa.Verify(pubKey, d1[:], r, s) {
		return true, "sha256(msg)"
	}

	// B) common bug: signer already hashed msg, and verifier hashes again (double hash mismatch)
	d2 := sha256.Sum256(d1[:])
	if ecdsa.Verify(pubKey, d2[:], r, s) {
		return true, "sha256(sha256(msg))"
	}

	// C) signer used the 32-byte digest directly as "msg" (i.e. server should NOT hash again)
	// Only makes sense if msg is already 32 bytes (it isn't in your case),
	// but keep for completeness.
	if len(msg) == 32 {
		if ecdsa.Verify(pubKey, msg, r, s) {
			return true, "msg_is_digest_32bytes"
		}
	}

	return false, "no_match"
}
