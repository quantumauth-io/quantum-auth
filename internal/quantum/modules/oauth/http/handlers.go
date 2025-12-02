package quantumhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Madeindreams/quantum-auth/internal/quantum/database"
	"github.com/Madeindreams/quantum-auth/internal/quantum/security"
	"github.com/Madeindreams/quantum-go-utils/log"

	//"github.com/Madeindreams/quantum-auth/internal/quantum/transport/http/middleware"
	//"github.com/Madeindreams/quantum-go-utils/log"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Handler struct {
	ctx  context.Context
	repo *database.QuantumAuthRepository
	rdb  *redis.Client
}

const nonceKeyPrefix = "qa:nonce:device:"

func (h *Handler) nextNonce(ctx context.Context, deviceID string) (int64, error) {
	if h.rdb == nil {
		return 0, fmt.Errorf("redis client not configured")
	}

	key := nonceKeyPrefix + deviceID

	// INCR is atomic in Redis.
	n, err := h.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	return n, nil
}

func NewHandler(ctx context.Context, repo *database.QuantumAuthRepository, rdb *redis.Client) *Handler {
	return &Handler{
		ctx:  ctx,
		repo: repo,
		rdb:  rdb,
	}
}

func NewChallenge(deviceID string, ttl time.Duration, nonce int64) *database.CreateChallengeInput {
	return &database.CreateChallengeInput{
		DeviceID:  deviceID,
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func NewDevice(userID, deviceLabel string, tpmPublicKey, pqPublicKey string) *database.CreateDeviceInput {
	return &database.CreateDeviceInput{
		UserID:       userID,
		DeviceLabel:  deviceLabel,
		TPMPublicKey: tpmPublicKey,
		PQPublicKey:  pqPublicKey,
	}
}

func buildSignedMessage(ch *database.Challenge, deviceID string) ([]byte, error) {
	msg := SignedMessage{
		ChallengeID: ch.ID,
		DeviceID:    deviceID,
		Nonce:       ch.Nonce,
		Purpose:     "auth",
	}
	return json.Marshal(msg)
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
	var req authChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id is required"})
		return
	}

	d, err := h.repo.GetDeviceByID(h.ctx, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if d == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	nonce, err := h.nextNonce(c.Request.Context(), req.DeviceID)
	if err != nil {
		c.String(http.StatusInternalServerError, "failed to generate nonce")
		return
	}

	// 2-minute TTL for now
	ch := NewChallenge(d.ID, 2*time.Minute, nonce)
	challengeId, err := h.repo.CreateChallenge(h.ctx, ch)

	resp := authChallengeResponse{
		ChallengeID: challengeId,
		Nonce:       nonce,
		ExpiresAt:   ch.ExpiresAt,
	}

	jsonBody, _ := json.Marshal(resp)
	log.Info("challenge response", "json", string(jsonBody))

	c.JSON(http.StatusCreated, resp)
}

// AuthVerify
// @BasePath /quantum-auth/v1
// @Summary      Verify auth response (hybrid TPM + PQ)
// @Description  Verifies a signed challenge response using TPM and PQ signatures plus password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        payload  body      authVerifyRequest   true  "Verify request"
// @Success      200      {object} authVerifyResponse
// @Failure      400      {string} string "invalid input"
// @Failure      401      {object} authVerifyResponse "invalid signature or password"
// @Failure      404      {string} string "challenge or device not found"
// @Router       /auth/verify [post]
func (h *Handler) AuthVerify(c *gin.Context) {
	var req authVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Info("auth verify request", "req", req)

	if req.ChallengeID == "" || req.DeviceID == "" || req.Password == "" ||
		req.TPMSignature == "" || req.PQSignature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge_id, device_id, password, tpm_signature, pq_signature are required"})
		return
	}

	ch, err := h.repo.GetChallenge(h.ctx, req.ChallengeID)
	if ch == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
		return
	}

	if ch.DeviceID != req.DeviceID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device id mismatch"})
		return
	}

	if time.Now().After(ch.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "challenge expired"})
		return
	}

	d, err := h.repo.GetDeviceByID(h.ctx, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if d == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	user, err := h.repo.GetUserByID(h.ctx, d.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// 1) verify password
	ok, err := security.VerifyPassword(user.PasswordHash, req.Password)
	log.Info("verify password",
		"hash", user.PasswordHash,
		"password", req.Password,
		"ok", ok,
		"err", err,
	)

	if err != nil {
		// if you want, treat internal error as 500
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	msgBytes, err := buildSignedMessage(ch, req.DeviceID)
	log.Info("server msg", "msg",
		base64.StdEncoding.EncodeToString(msgBytes))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 3) verify TPM signature
	okTPM := security.VerifyTPMSignature(d.TPMPublicKey, msgBytes, req.TPMSignature)
	log.Info("verify TPM", "ok", okTPM)
	if !okTPM {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// 4) verify PQ signature
	okPQ := security.VerifyPQSignature(d.PQPublicKey, msgBytes, req.PQSignature)
	log.Info("verify PQ", "ok", okPQ)
	if !okPQ {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// success: destroy challenge to prevent replay
	err = h.repo.DeleteChallenge(h.ctx, ch.ID)
	if err != nil {
		log.Error("Error deleting challenge: ", "error", err)
		return
	}

	c.JSON(http.StatusOK, authVerifyResponse{
		Authenticated: true,
		UserID:        user.ID,
	})
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
	var req registerDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Info("request", "device", req)

	if req.UserId == "" || req.DeviceLabel == "" || req.TPMPublicKey == "" || req.PQPublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id, device_label, tpm_public_key and pq_public_key are required"})
		return
	}
	u, err := h.repo.GetUserByID(h.ctx, req.UserId)
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
	deviceId, err := h.repo.CreateDevice(h.ctx, d)
	if err != nil {
		log.Error("failed to create device", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	_ = registerDeviceResponse{DeviceID: deviceId}
	log.Info("response", "device", deviceId)
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
