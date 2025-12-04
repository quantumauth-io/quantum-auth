package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type CanonicalInput struct {
	Method string
	Path   string
	Host   string

	TS       int64
	Nonce    int64
	UserID   string
	DeviceID string

	Body []byte
}

func CanonicalString(ci CanonicalInput) string {
	bodyHash := sha256.Sum256(ci.Body)

	return strings.Join([]string{
		strings.ToUpper(ci.Method),
		ci.Path,
		ci.Host,
		fmt.Sprintf("TS: %d", ci.TS),
		fmt.Sprintf("NONCE: %d", ci.Nonce),
		fmt.Sprintf("USER: %s", ci.UserID),
		fmt.Sprintf("DEVICE: %s", ci.DeviceID),
		fmt.Sprintf("BODY-SHA256: %s", hex.EncodeToString(bodyHash[:])),
	}, "\n")
}
