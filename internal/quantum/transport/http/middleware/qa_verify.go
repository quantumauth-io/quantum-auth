package middleware

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
	"github.com/gin-gonic/gin"
	qdb "github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-auth/pkg/qa/requests"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

var pqScheme sign.Scheme

// QuantumAuthRepository is the subset of repo methods used by the HTTP layer.
type QuantumAuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*qdb.User, error)
	CreateUser(ctx context.Context, in qdb.CreateUserInput) (string, error)

	GetUserByID(ctx context.Context, id string) (*qdb.User, error)

	GetDeviceByID(ctx context.Context, id string) (*qdb.Device, error)
	CreateDevice(ctx context.Context, in *qdb.CreateDeviceInput) (string, error)

	CreateChallenge(ctx context.Context, in *qdb.CreateChallengeInput) (string, error)
	DeleteChallenge(ctx context.Context, id string) error
}

func init() {
	pqScheme = schemes.ByName("ML-DSA-65")
	if pqScheme == nil {
		panic("PQ scheme ML-DSA-65 not found in CIRCL")
	}
}

// Config for the QuantumAuth middleware.
type Config struct {
	Repo     QuantumAuthRepository
	NonceTTL time.Duration // replay window for nonces; default 5m if zero
}

// QuantumAuthMiddleware verifies TPM + PQ signatures and checks replay via Redis.
func QuantumAuthMiddleware(cfg Config) gin.HandlerFunc {
	if cfg.NonceTTL == 0 {
		cfg.NonceTTL = 5 * time.Minute
	}

	return func(c *gin.Context) {
		r := c.Request
		ctx := r.Context()

		// 1. Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "QuantumAuth ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing QuantumAuth header"})
			return
		}

		params := parseAuthParams(auth[len("QuantumAuth "):])
		challengeID := params["challenge"]
		sigTPM := params["sig_tpm"]
		sigPQ := params["sig_pq"]

		if challengeID == "" || sigTPM == "" || sigPQ == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "incomplete QuantumAuth header"})
			return
		}

		// 2) Find canonical from header
		canonicalB64 := r.Header.Get("X-QuantumAuth-Canonical-B64")
		if canonicalB64 == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing X-QuantumAuth-Canonical-B64 header"})
			return
		}

		msgBytes, err := base64.StdEncoding.DecodeString(canonicalB64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid canonical base64"})
			return
		}

		parsed, err := requests.ParseCanonicalString(string(msgBytes))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid canonical format"})
			return
		}

		// now you have:
		userID := parsed.UserID
		deviceID := parsed.DeviceID
		challengeID = parsed.ChallengeID
		ts := parsed.TS
		_ = parsed.BodySHA256 // unused for now

		// (optional) debug: log canonical
		log.Info("canonical", "value", string(msgBytes), "ts", ts, "challenge", challengeID)

		now := time.Now().Unix()
		if math.Abs(float64(now-ts)) > 30 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "timestamp skew"})
			return
		}

		err = cfg.Repo.DeleteChallenge(ctx, challengeID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "challenge delete error"})
		}

		// 4. Load device from DB to get public keys
		dev, err := cfg.Repo.GetDeviceByID(ctx, deviceID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if dev == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid device"})
			return
		}

		// 5. Buffer body so handlers can still read it
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		// IMPORTANT: canonical path must match what the client signed.
		// If your public base path is /quantum-auth/v1, the client should
		// sign "/quantum-auth/v1/api/secure-ping" or you should strip the prefix here.
		canonical := requests.CanonicalString(requests.CanonicalInput{
			Method:      r.Method,
			Path:        r.URL.Path,
			Host:        r.Host,
			TS:          ts,
			ChallengeID: challengeID,
			UserID:      userID,
			DeviceID:    deviceID,
			Body:        body,
		})

		// 6. Verify TPM signature
		if !verifyTPM(dev.TPMPublicKey, canonical, sigTPM) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid TPM signature"})
			return
		}

		// 7. Verify PQ signature
		if !verifyPQ(dev.PQPublicKey, canonical, sigPQ) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid PQ signature"})
			return
		}

		// 8. Inject user & device into context
		c.Set("userID", userID)
		c.Set("deviceID", deviceID)

		c.Next()
	}
}

// ----------------- helpers -----------------

func parseAuthParams(s string) map[string]string {
	out := make(map[string]string)
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		val = strings.Trim(val, `"`)
		out[key] = val
	}
	return out
}

func verifyTPM(pubB64, canonical, sigB64 string) bool {
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubB64)
	if err != nil {
		return false
	}
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return false
	}
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:])

	pub := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	sigBytes, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	if len(sigBytes) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	h := sha256.Sum256([]byte(canonical))
	return ecdsa.Verify(&pub, h[:], r, s)
}

func verifyPQ(pubB64, canonical, sigB64 string) bool {
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubB64)
	if err != nil {
		return false
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}

	pk, err := pqScheme.UnmarshalBinaryPublicKey(pubBytes)
	if err != nil {
		return false
	}

	return pqScheme.Verify(pk, []byte(canonical), sigBytes, nil)
}
