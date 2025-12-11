package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	qdb "github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/security"
	"github.com/quantumauth-io/quantum-auth/pkg/qa/requests"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

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
type Handler struct {
	ctx  context.Context
	repo QuantumAuthRepository
}

func NewHandler(ctx context.Context, repo QuantumAuthRepository) *Handler {
	return &Handler{
		ctx:  ctx,
		repo: repo,
	}
}

func NewChallenge(deviceID string, ttl time.Duration) *qdb.CreateChallengeInput {
	return &qdb.CreateChallengeInput{
		DeviceID:  deviceID,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func NewDevice(userID, deviceLabel string, tpmPublicKey, pqPublicKey string) *qdb.CreateDeviceInput {
	return &qdb.CreateDeviceInput{
		UserID:       userID,
		DeviceLabel:  deviceLabel,
		TPMPublicKey: tpmPublicKey,
		PQPublicKey:  pqPublicKey,
	}
}

// RegisterUser godoc
// @BasePath /quantum-auth/v1
// @Summary     Signup
// @Description Create a user account
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       payload body SignupRequest true "Signup payload"
// @Success     201 {object} map[string]string
// @Failure     400 {object} map[string]string
// @Router      /users/register [post]
func (h *Handler) RegisterUser(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if email already exists
	if u, _ := h.repo.GetUserByEmail(c.Request.Context(), req.Email); u != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already registered"})
		return
	}

	passwordHash, err := security.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash error"})
		return
	}

	u := &database.CreateUserInput{
		Email:     req.Email,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Password:  passwordHash,
	}

	id, err := h.repo.CreateUser(c.Request.Context(), *u)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create user failed"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user_id": id})
}

// AuthChallenge
// @BasePath /quantum-auth/v1
// @Summary      Issue auth challenge
// @Description  Issues a short-lived challenge (nonce) for a registered device
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      authChallengeRequest   true  "Challenge request"
// @Success      201      {object} authChallengeResponse
// @Failure      400      {string} string "invalid input"
// @Failure      404      {string} string "device not found"
// @Router       /auth/challenge [post]
func (h *Handler) AuthChallenge(c *gin.Context) {
	ctx := c.Request.Context()
	var req authChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id is required"})
		return
	}

	d, err := h.repo.GetDeviceByID(ctx, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if d == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	// 2-minute TTL for now
	ch := NewChallenge(d.ID, 2*time.Minute)
	challengeId, err := h.repo.CreateChallenge(ctx, ch)

	resp := authChallengeResponse{
		ChallengeID: challengeId,
		ExpiresAt:   ch.ExpiresAt,
	}

	c.JSON(http.StatusCreated, resp)
}

// AuthVerify
// @BasePath /quantum-auth/v1
// @Summary      Verify signed QuantumAuth request
// @Description  Verifies TPM + PQ signatures in the Authorization header for an API request
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      authVerifyRequest   true  "Verify request"
// @Success      200      {object}  authVerifyResponse
// @Failure      400      {string}  string "invalid input"
// @Failure      401      {object}  authVerifyResponse "unauthorized"
// @Failure      404      {string}  string "user or device not found"
// @Router       /auth/verify [post]
func (h *Handler) AuthVerify(c *gin.Context) {
	ctx := c.Request.Context()
	var req authVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Method == "" || req.Path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "method and path are required"})
		return
	}

	// headers from Node middleware (keys likely lowercase)
	if req.Headers == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "headers are required"})
		return
	}

	// 1) Extract Authorization header
	authHeader := ""
	for k, v := range req.Headers {
		if strings.ToLower(k) == "authorization" {
			authHeader = v
			break
		}
	}

	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	fields, err := parseQuantumAuthHeader(authHeader)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Authorization header"})
		return
	}

	challengeID := fields["challenge"]
	sigTPM := fields["sig_tpm"]
	sigPQ := fields["sig_pq"]

	if sigTPM == "" || sigPQ == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing fields in Authorization header"})
		return
	}

	// 2) Find canonical from header
	canonicalB64 := ""
	for k, v := range req.Headers {
		if strings.ToLower(k) == "x-quantumauth-canonical-b64" {
			canonicalB64 = v
			break
		}
	}
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

	userID := parsed.UserID
	deviceID := parsed.DeviceID
	challengeID = parsed.ChallengeID

	// 2) Get Host header (needed for canonical string)
	host := ""
	for k, v := range req.Headers {
		if strings.ToLower(k) == "host" {
			host = v
			break
		}
	}
	if host == "" {
		host = "unknown"
	}

	// 3) Look up device + user
	d, err := h.repo.GetDeviceByID(ctx, deviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if d == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	if d.UserID != userID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "device does not belong to user"})
		return
	}

	user, err := h.repo.GetUserByID(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	err = h.repo.DeleteChallenge(ctx, challengeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	// 5) Verify TPM signature
	okTPM := security.VerifyTPMSignature(d.TPMPublicKey, msgBytes, sigTPM)
	if !okTPM {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized (TPM)"})
		return
	}

	// 6) Verify PQ signature
	okPQ := security.VerifyPQSignature(d.PQPublicKey, msgBytes, sigPQ)
	if !okPQ {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized (PQ)"})
		return
	}

	// TODO: if you want, you can also:
	//  - verify X-QuantumAuth-Challenge-ID exists & not expired
	//  - track/reject replayed Authorization nonces in Redis

	c.JSON(http.StatusOK, authVerifyResponse{
		Authenticated: true,
		UserID:        user.ID,
	})
}

func parseQuantumAuthHeader(auth string) (map[string]string, error) {
	const prefix = "QuantumAuth "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("invalid scheme")
	}
	rest := strings.TrimSpace(auth[len(prefix):])
	parts := strings.Split(rest, ",")
	fields := make(map[string]string, len(parts))

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
		fields[key] = val
	}
	return fields, nil
}

// RegisterDevice
// @BasePath /quantum-auth/v1
// @Summary      Register device
// @Description  Registers a new authentication device (TPM + PQ keys) for an existing user
// @Tags         devices
// @Accept       json
// @Produce      json
// @Param        payload  body      registerDeviceRequest  true  "Device registration"
// @Success      201      {object}  registerDeviceResponse
// @Failure      400      {string}  string  "invalid input"
// @Failure      404      {string}  string  "user not found"
// @Router       /devices/register [post]
func (h *Handler) RegisterDevice(c *gin.Context) {
	ctx := c.Request.Context()
	var req registerDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.UserId == "" || req.DeviceLabel == "" || req.TPMPublicKey == "" || req.PQPublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id, device_label, tpm_public_key and pq_public_key are required"})
		return
	}
	u, err := h.repo.GetUserByID(ctx, req.UserId)
	if err != nil {
		log.Error("GetUserByEmail", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if u == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return

	}

	d := NewDevice(u.ID, req.DeviceLabel, req.TPMPublicKey, req.PQPublicKey)
	deviceId, err := h.repo.CreateDevice(ctx, d)
	if err != nil {
		log.Error("failed to create device", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	_ = registerDeviceResponse{DeviceID: deviceId}
	c.JSON(http.StatusCreated, gin.H{"device_id": deviceId})
}

// SecurePing
// @BasePath /quantum-auth/v1
// @Summary      Quantum-secured ping
// @Description  Confirms that the request was authenticated using TPM + PQ signatures.
// @Tags         secure
// @Produce      json
// @Success      200  {object}  SecurePingResponse
// @Failure      401  {string}  string  "unauthorized"
// @Router       /api/secure-ping [get]
func (h *Handler) SecurePing(c *gin.Context) {
	// Extract values set by the QuantumAuth middleware
	userID, _ := c.Get("userID")
	deviceID, _ := c.Get("deviceID")

	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"message":   "Quantum-authenticated request successful",
		"user_id":   userID,
		"device_id": deviceID,
	})
}

// FullLogin
// @BasePath /quantum-auth/v1
// @Summary      Full device login (password + TPM + PQ)
// @Description  Authenticates a device by verifying the user's password and both TPM & PQ signatures over a login message.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      fullLoginRequest   true  "Full login request"
// @Success      200      {object}  fullLoginResponse
// @Failure      400      {string}  string  "invalid input"
// @Failure      401      {string}  string  "unauthorized"
// @Failure      404      {string}  string  "user or device not found"
// @Router       /auth/full-login [post]
func (h *Handler) FullLogin(c *gin.Context) {
	ctx := c.Request.Context()
	var req fullLoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.UserID == "" || req.DeviceID == "" || req.Password == "" ||
		req.MessageB64 == "" || req.TPMSignature == "" || req.PQSignature == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user_id, device_id, password, message, tpm_signature, pq_signature are required",
		})
		return
	}

	// 1) Load device
	d, err := h.repo.GetDeviceByID(ctx, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if d == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	if d.UserID != req.UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device does not belong to user"})
		return
	}

	// 2) Load user
	user, err := h.repo.GetUserByID(ctx, req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// 3) Verify password
	ok, err := security.VerifyPassword(user.PasswordHash, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// 4) Parse and validate the login message
	type loginMessage struct {
		UserID   string `json:"user_id"`
		DeviceID string `json:"device_id"`
		Purpose  string `json:"purpose"`
		TS       int64  `json:"ts"`
	}

	msgBytes, err := base64.StdEncoding.DecodeString(req.MessageB64)
	var msg loginMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid message JSON"})
		return
	}

	if msg.UserID != req.UserID || msg.DeviceID != req.DeviceID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message user/device mismatch"})
		return
	}
	if msg.Purpose != "client-login" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid message purpose"})
		return
	}

	if time.Since(time.Unix(msg.TS, 0)) > 5*time.Minute {
		c.JSON(http.StatusBadRequest, gin.H{"error": "login message too old"})
		return
	}

	// 5) Verify TPM signature
	okTPM := security.VerifyTPMSignature(d.TPMPublicKey, msgBytes, req.TPMSignature)
	if !okTPM {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// 6) Verify PQ signature
	okPQ := security.VerifyPQSignature(d.PQPublicKey, msgBytes, req.PQSignature)
	if !okPQ {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// success
	c.JSON(http.StatusOK, fullLoginResponse{
		Authenticated: true,
		UserID:        user.ID,
		DeviceID:      d.ID,
	})
}
