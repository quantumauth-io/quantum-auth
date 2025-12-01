package middleware

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"

	"github.com/Madeindreams/quantum-auth/pkg/qa/requests"
)

var (
	// PQ scheme (same as device-client)
	pqScheme sign.Scheme

	// in-memory device key store (temporary until DB is wired)
	deviceMu sync.RWMutex
	devices  = make(map[string]DeviceKeys)

	// in-memory nonce store for replay protection
	nonceMu   sync.Mutex
	nonceSeen = make(map[string]map[string]struct{})
)

func init() {
	pqScheme = schemes.ByName("ML-DSA-65")
	if pqScheme == nil {
		panic("PQ scheme ML-DSA-65 not found in CIRCL")
	}
}

// DeviceKeys holds the public keys needed for verification.
type DeviceKeys struct {
	TPMPublic string // base64(0x04 || X || Y)
	PQPublic  string // base64(ML-DSA public key)
}

// RegisterDeviceKeys is a helper you can call from your
// /devices/register handler until you have a real DB wired.
//
// Call it like:
//
//	middleware.RegisterDeviceKeys(deviceID, tpmPubB64, pqPubB64)
func RegisterDeviceKeys(deviceID, tpmPubB64, pqPubB64 string) {
	deviceMu.Lock()
	defer deviceMu.Unlock()
	devices[deviceID] = DeviceKeys{
		TPMPublic: tpmPubB64,
		PQPublic:  pqPubB64,
	}
}

func getDeviceKeys(deviceID string) (DeviceKeys, error) {
	deviceMu.RLock()
	defer deviceMu.RUnlock()
	dev, ok := devices[deviceID]
	if !ok {
		return DeviceKeys{}, errors.New("device not found")
	}
	return dev, nil
}

// QuantumAuthMiddleware verifies per-request signatures from TPM + PQ keys.
func QuantumAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// 1. Parse Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "QuantumAuth ") {
			http.Error(w, "missing QuantumAuth header", http.StatusUnauthorized)
			return
		}

		params := parseAuthParams(auth[len("QuantumAuth "):])
		userID := params["user"]
		deviceID := params["device"]
		tsStr := params["ts"]
		nonce := params["nonce"]
		sigTPM := params["sig_tpm"]
		sigPQ := params["sig_pq"]

		if userID == "" || deviceID == "" || tsStr == "" || nonce == "" || sigTPM == "" || sigPQ == "" {
			http.Error(w, "incomplete QuantumAuth header", http.StatusUnauthorized)
			return
		}

		// 2. Validate timestamp
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid timestamp", http.StatusUnauthorized)
			return
		}
		now := time.Now().Unix()
		if math.Abs(float64(now-ts)) > 30 {
			http.Error(w, "timestamp skew", http.StatusUnauthorized)
			return
		}

		// 3. Validate nonce for replay protection
		if seenBefore(deviceID, nonce) {
			http.Error(w, "replay detected", http.StatusUnauthorized)
			return
		}

		// 4. Load public keys (currently from in-memory store)
		dev, err := getDeviceKeys(deviceID)
		if err != nil {
			http.Error(w, "invalid device", http.StatusUnauthorized)
			return
		}

		// Read and buffer body so handlers can still read it
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		// 5. Build canonical string
		canonical := requests.CanonicalString(requests.CanonicalInput{
			Method:   r.Method,
			Path:     r.URL.Path,
			Host:     r.Host,
			TS:       ts,
			Nonce:    nonce,
			UserID:   userID,
			DeviceID: deviceID,
			Body:     body,
		})

		// 6. Verify TPM signature
		if !verifyTPM(dev.TPMPublic, canonical, sigTPM) {
			http.Error(w, "invalid TPM signature", http.StatusUnauthorized)
			return
		}

		// 7. Verify PQ signature
		if !verifyPQ(dev.PQPublic, canonical, sigPQ) {
			http.Error(w, "invalid PQ signature", http.StatusUnauthorized)
			return
		}

		// 8. Mark nonce as used
		saveNonce(deviceID, nonce)

		// 9. Inject user & device into request context
		ctx := context.WithValue(r.Context(), "userID", userID)
		ctx = context.WithValue(ctx, "deviceID", deviceID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

// parseAuthParams parses:
//
//	user="...", device="...", ts="...", ...
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

// seenBefore checks if nonce was already used for this device.
func seenBefore(deviceID, nonce string) bool {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	perDev, ok := nonceSeen[deviceID]
	if !ok {
		return false
	}
	_, exists := perDev[nonce]
	return exists
}

// saveNonce marks nonce as used for this device.
func saveNonce(deviceID, nonce string) {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	perDev, ok := nonceSeen[deviceID]
	if !ok {
		perDev = make(map[string]struct{})
		nonceSeen[deviceID] = perDev
	}
	perDev[nonce] = struct{}{}
}

// verifyTPM verifies base64(R||S) against base64(0x04||X||Y) over canonical string.
func verifyTPM(pubB64, canonical, sigB64 string) bool {
	pubBytes, err := base64.RawStdEncoding.DecodeString(pubB64)
	if err != nil {
		return false
	}
	// Expect uncompressed EC point: 0x04 || X || Y, 32 bytes each
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

// verifyPQ verifies ML-DSA-65 signature (base64) using circl.
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

	// circl returns error on failure, nil on success
	if err := pqScheme.Verify(pk, []byte(canonical), sigBytes, nil); err {
		return false
	}
	return true
}
