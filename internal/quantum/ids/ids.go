package ids

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

// UUIDStringToBytes32 converts a UUID v4 string into a bytes32 representation:
// left-padded with zeros, UUID bytes in the last 16 bytes.
func UUIDStringToBytes32(s string) ([32]byte, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("parse uuid: %w", err)
	}
	var out [32]byte
	copy(out[16:], u[:]) // last 16 bytes
	return out, nil
}

// Bytes32ToUUIDString converts a bytes32 back into a UUID string by taking the last 16 bytes.
func Bytes32ToUUIDString(b [32]byte) (string, error) {
	u, err := uuid.FromBytes(b[16:])
	if err != nil {
		return "", fmt.Errorf("from bytes: %w", err)
	}
	return u.String(), nil
}

// Convenience: [32]byte -> common.Hash (handy for typed data message)
func Bytes32ToHash(b [32]byte) common.Hash {
	return common.BytesToHash(b[:])
}
