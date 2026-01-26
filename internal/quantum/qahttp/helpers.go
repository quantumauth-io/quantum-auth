package qahttp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
)

func toAppResponse(a *database.App) appResponse {
	desc := a.Description
	return appResponse{
		AppID:             a.AppID,
		OwnerUserID:       a.OwnerUserID,
		Name:              a.Name,
		Description:       desc,
		Domain:            a.Domain,
		BackendHost:       a.BackendHost,
		Tier:              a.Tier,
		Verified:          a.Verified,
		VerificationToken: a.VerificationToken,
		PQPublicKeyB64:    encodePQKeyB64(a.PQPublicKey),
		LastVerifiedAt:    a.LastVerifiedAt,
		LastCheckedAt:     a.LastCheckedAt,
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}

func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	return &v
}

// token: URL-safe, copy/paste friendly
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodePQKeyB64(s string) ([]byte, error) {
	// allow whitespace in pasted strings
	clean := strings.TrimSpace(s)
	if clean == "" {
		return nil, fmt.Errorf("empty pq public key")
	}

	b, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("invalid base64")
		}
	}

	if len(b) != constants.MlDSA65PublicKeyLen {
		return nil, fmt.Errorf("pq public key must be %d bytes", constants.MlDSA65PublicKeyLen)
	}

	return b, nil
}

func encodePQKeyB64(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := base64.StdEncoding.EncodeToString(b)

	return &s
}

func swaggerEnabled() bool {
	switch os.Getenv("QA_ENV") {
	case "develop", "local", "staging":
		return true
	default:
		return false
	}
}
