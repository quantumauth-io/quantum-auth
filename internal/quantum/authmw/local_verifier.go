package authmw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/quantumauth-io/go-quantumauth-mw"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/authheader"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/security"
	"github.com/quantumauth-io/quantum-go-utils/qa/headers"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"
)

type Repo interface {
	GetDeviceByID(ctx context.Context, deviceID string) (*database.Device, error)
	ConsumeChallenge(ctx context.Context, challengeID string, DecideID string, UserId string) error
	GetAppByID(ctx context.Context, appID string) (*database.App, error)
}

type Device struct {
	ID           string
	UserID       string
	TPMPublicKey string
	PQPublicKey  string
}

type User struct {
	ID string
}

type LocalVerifier struct {
	Repo *database.QuantumAuthRepository
}

func (v *LocalVerifier) Verify(ctx context.Context, in qaauthmw.VerifyInput) (*qaauthmw.VerifyResult, error) {

	badReq := func(msg string, kv ...any) (*qaauthmw.VerifyResult, error) {
		return nil, fmt.Errorf("%w: %s", qaauthmw.ErrBadRequest, msg)
	}
	unauth := func(msg string, kv ...any) (*qaauthmw.VerifyResult, error) {
		return &qaauthmw.VerifyResult{Authenticated: false}, qaauthmw.ErrUnauthorized
	}
	getHeader := func(name string) string {
		for k, v := range in.Headers {
			if strings.EqualFold(k, name) {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	preview := func(s string, n int) string {
		s = strings.TrimSpace(s)
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	}

	sha256HexStr := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}

	// --- basic input validation
	if strings.TrimSpace(in.Method) == "" || strings.TrimSpace(in.Path) == "" {
		return badReq("missing method/path", "method", in.Method, "path", in.Path)
	}
	if len(in.Headers) == 0 {
		return badReq("missing headers")
	}

	// --- pull headers
	authHeader := getHeader(string(headers.HeaderAuthorization))
	appID := getHeader(string(headers.HeaderQAAppID))
	aud := getHeader(string(headers.HeaderQAAudience))
	tsStr := getHeader(string(headers.HeaderQATimestamp))
	challengeID := getHeader(string(headers.HeaderQAChallengeID))
	userID := getHeader(string(headers.HeaderQAUserID))
	deviceID := getHeader(string(headers.HeaderQADeviceID))
	bodySHA256 := getHeader(string(headers.HeaderQABodySHA256))
	ver := getHeader(string(headers.HeaderQAVersion))

	if authHeader == "" {
		return unauth("missing Authorization")
	}

	fields, err := authheader.ParseQuantumAuthHeader(authHeader)
	if err != nil {
		return badReq("invalid Authorization header", "err", err.Error())
	}
	sigTPM := strings.TrimSpace(fields["sig_tpm"])
	sigPQ := strings.TrimSpace(fields["sig_pq"])
	if sigTPM == "" || sigPQ == "" {
		return badReq("missing sig fields")
	}

	if ver != "" && ver != constants.QAHeaderSigVersion {
		return badReq("unsupported signature version", "ver", ver, "expected", constants.QAHeaderSigVersion)
	}

	if appID, err = requests.ValidateUUIDv4(appID); err != nil {
		return badReq("invalid app id", "appId", appID)
	}
	if challengeID, err = requests.ValidateUUIDv4(challengeID); err != nil {
		return badReq("invalid challenge id", "challengeId", challengeID)
	}
	if userID, err = requests.ValidateUUIDv4(userID); err != nil {
		return badReq("invalid user id", "userId", userID)
	}
	if deviceID, err = requests.ValidateUUIDv4(deviceID); err != nil {
		return badReq("invalid device id", "deviceId", deviceID)
	}

	ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil || ts <= 0 {
		return badReq("invalid timestamp", "ts", tsStr)
	}
	now := time.Now().Unix()
	skew := now - ts
	if ts < now-300 || ts > now+60 {
		return unauth("timestamp outside skew window", "now", now, "ts", ts, "skewSeconds", skew)
	}

	// body sha validation
	bodySHA256 = strings.ToLower(strings.TrimSpace(bodySHA256))
	if bodySHA256 == "" {
		return badReq("missing body sha256")
	}
	if len(bodySHA256) != 64 {
		return badReq("invalid body sha256 length", "len", len(bodySHA256))
	}
	if _, err := hex.DecodeString(bodySHA256); err != nil {
		return badReq("invalid body sha256 hex", "err", err.Error())
	}

	audNorm := requests.NormalizeBackendHost(aud)
	if audNorm == "" {
		return badReq("invalid aud", "aud", aud)
	}

	app, err := v.Repo.GetAppByID(ctx, appID)
	if err != nil {
		return nil, fmt.Errorf("get app: %w", err)
	}
	if app == nil {
		return unauth("unknown app", "appId", appID)
	}

	expectedAud := requests.NormalizeBackendHost(app.BackendHost)
	if expectedAud == "" {
		return nil, fmt.Errorf("app misconfigured: empty backend_host")
	}
	if audNorm != expectedAud {
		return unauth("aud mismatch 2", "audNorm", audNorm, "expectedAud", expectedAud, "audRaw", aud)
	}

	// normalize method/path
	method, err := requests.NormalizeAndValidateMethod(in.Method)
	if err != nil {
		return badReq("invalid method", "err", err.Error())
	}
	path, err := requests.NormalizeAndValidatePath(in.Path, requests.PathNormalizeOptions{CollapseSlashes: false})
	if err != nil {
		return badReq("invalid path", "err", err.Error(), "path", in.Path)
	}

	// canonical
	canonical, err := requests.CanonicalString(requests.CanonicalInput{
		Method:        method,
		Path:          path,
		AppID:         appID,
		BackendHost:   expectedAud,
		TS:            ts,
		ChallengeID:   challengeID,
		UserID:        userID,
		DeviceID:      deviceID,
		BodySHA256Hex: bodySHA256,
	})
	if err != nil {
		return badReq("canonical build failed", "err", err.Error())
	}

	canonicalSha := sha256HexStr(canonical)
	msgBytes := []byte(canonical)

	// load device
	d, err := v.Repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}
	if d == nil {
		return unauth("unknown device", "deviceId", deviceID)
	}
	if d.UserID != userID {
		return unauth("device not owned by user", "deviceUserId", d.UserID, "userId", userID)
	}

	// verify signatures
	// verify signatures
	if ok := security.VerifyTPMSignature(d.TPMPublicKey, msgBytes, sigTPM); !ok {
		return unauth("tpm signature invalid",
			"canonicalSha256", canonicalSha,
			"sigTPM_b64_preview", preview(sigTPM, 32),
		)
	}
	if ok := security.VerifyPQSignature(d.PQPublicKey, msgBytes, sigPQ); !ok {
		return unauth("pq signature invalid",
			"canonicalSha256", canonicalSha,
			"sigPQ_b64_preview", preview(sigPQ, 32),
		)
	}

	if err := v.Repo.ConsumeChallenge(ctx, challengeID, deviceID, appID); err != nil {
		if errors.Is(err, database.ErrChallengeNotFoundOrAlreadyUsed) {
			return unauth("challenge not found or already used", "challengeId", challengeID)
		}
		return nil, fmt.Errorf("consume challenge: %w", err)
	}

	return &qaauthmw.VerifyResult{
		Authenticated: true,
		UserID:        d.UserID,
	}, nil
}
