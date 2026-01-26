package qahttp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/authheader"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/email"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/security"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa/headers"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"
)

// QuantumAuthRepository is the subset of repo methods used by the HTTP layer.
type QuantumAuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*database.User, error)
	CreateUser(ctx context.Context, in database.CreateUserInput) (string, error)

	GetUserByID(ctx context.Context, id string) (*database.User, error)

	GetDeviceByID(ctx context.Context, id string) (*database.Device, error)
	CreateDevice(ctx context.Context, in *database.CreateDeviceInput) (string, error)

	CreateChallenge(ctx context.Context, in *database.CreateChallengeInput) (string, error)
	DeleteChallenge(ctx context.Context, id string) error

	SubscribeNewsletter(ctx context.Context, in database.SubscribeNewsletterInput) (string, error)
	UnsubscribeNewsletter(ctx context.Context, in database.UnsubscribeNewsletterInput) (string, error)
	GetNewsletterByEmail(ctx context.Context, email string) (*database.NewsletterSubscription, error)
}
type Handler struct {
	ctx         context.Context
	repo        *database.QuantumAuthRepository
	emailSender *email.SMTPSender
}

func NewHandler(ctx context.Context, repo *database.QuantumAuthRepository, emailSender *email.SMTPSender) *Handler {
	return &Handler{
		ctx:         ctx,
		repo:        repo,
		emailSender: emailSender,
	}
}

func NewChallenge(deviceID string, ttl time.Duration, appID string) *database.CreateChallengeInput {
	return &database.CreateChallengeInput{
		DeviceID:  deviceID,
		AppID:     appID,
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

	passwordHash, err := security.HashPassword(req.PasswordB64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash error"})
		log.Error("registerUser:", "error", err)
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
		log.Error("registerUser:", "error", err)
		return
	}

	docsURL := constants.EmailDocsUrl
	logoURL := constants.EmailLogoUrl

	err = h.emailSender.Send(c, email.Message{
		FromName: constants.EmailFromName,
		FromAddr: constants.EmailFromAddress,
		To:       req.Email,
		Subject:  constants.EmailWelcomeSubject,
		TextBody: email.WelcomeEmailText(req.Username, docsURL),
		HTMLBody: email.WelcomeEmailHTML(req.Username, docsURL, logoURL),
	})

	if err != nil {
		log.Error("registerUser:", "error", err)
		// return user id even if email do not go through
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

	if req.AppID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_id is required"})
		return
	}

	d, err := h.repo.GetDeviceByID(ctx, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("authChallenge:", "error", err)
		return
	}

	if d == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	ch := NewChallenge(d.ID, 2*time.Minute, req.AppID)
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
	if req.Headers == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "headers are required"})
		return
	}

	getHeader := func(name string) string {
		for k, v := range req.Headers {
			if strings.EqualFold(k, name) {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}

	authHeader := getHeader(string(headers.HeaderAuthorization))
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
		return
	}

	fields, err := authheader.ParseQuantumAuthHeader(authHeader)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Authorization header"})
		return
	}
	sigTPM := fields["sig_tpm"]
	sigPQ := fields["sig_pq"]
	if sigTPM == "" || sigPQ == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing fields in Authorization header"})
		return
	}

	appID := getHeader(string(headers.HeaderQAAppID))
	aud := getHeader(string(headers.HeaderQAAudience))
	tsStr := getHeader(string(headers.HeaderQATimestamp))
	challengeID := getHeader(string(headers.HeaderQAChallengeID))
	userID := getHeader(string(headers.HeaderQAUserID))
	deviceID := getHeader(string(headers.HeaderQADeviceID))
	bodySHA256 := getHeader(string(headers.HeaderQABodySHA256))

	ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil || ts <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timestamp is invalid"})
		return
	}

	now := time.Now().Unix()
	if ts < now-300 || ts > now+60 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "timestamp out of range"})
		return
	}

	if bodySHA256 == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing body sha256"})
		return
	}

	bodySHA256 = strings.ToLower(strings.TrimSpace(bodySHA256))
	if len(bodySHA256) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body sha256 length"})
		return
	}
	if _, err := hex.DecodeString(bodySHA256); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body sha256 hex"})
		return
	}

	ver := getHeader(string(headers.HeaderQAVersion))
	if ver != "" && ver != constants.QAHeaderSigVersion {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported signature version"})
		return
	}

	var vErr error
	if appID, vErr = requests.ValidateUUIDv4(appID); vErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid app id"})
		return
	}
	if challengeID, vErr = requests.ValidateUUIDv4(challengeID); vErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid challenge id"})
		return
	}
	if userID, vErr = requests.ValidateUUIDv4(userID); vErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}
	if deviceID, vErr = requests.ValidateUUIDv4(deviceID); vErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device id"})
		return
	}

	audNorm := requests.NormalizeBackendHost(aud)
	if audNorm == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid aud"})
		return
	}

	app, err := h.repo.GetAppByID(ctx, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("authVerify:", "error", err)
		return
	}

	if app == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "app not found"})
		return
	}

	expectedAud := requests.NormalizeBackendHost(app.BackendHost)

	if expectedAud == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server misconfigured (aud)"})
		return
	}
	if audNorm != expectedAud {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "aud mismatch"})
		return
	}

	method, err := requests.NormalizeAndValidateMethod(req.Method)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	path, err := requests.NormalizeAndValidatePath(req.Path, requests.PathNormalizeOptions{
		CollapseSlashes: false,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return

	}
	msgBytes := []byte(canonical)

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

	okTPM := security.VerifyTPMSignature(d.TPMPublicKey, msgBytes, sigTPM)
	if !okTPM {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized (TPM)"})
		return
	}

	okPQ := security.VerifyPQSignature(d.PQPublicKey, msgBytes, sigPQ)
	if !okPQ {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized (PQ)"})
		return
	}

	if err := h.repo.ConsumeChallenge(ctx, challengeID, deviceID, appID); err != nil {
		if errors.Is(err, database.ErrChallengeNotFoundOrAlreadyUsed) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or already used challenge"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("authVerify:", "error", err)
		return
	}

	c.JSON(http.StatusOK, authVerifyResponse{
		Authenticated: true,
		UserID:        userID,
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
	ctx := c.Request.Context()
	var req registerDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.UserEmail == "" || req.DeviceLabel == "" || req.TPMPublicKey == "" || req.PQPublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id, device_label, tpm_public_key and pq_public_key are required"})
		return
	}
	u, err := h.repo.GetUserByEmail(ctx, req.UserEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("registerDevice:", "error", err)
		return
	}
	if u == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad request"})
		return
	}

	// 3) Verify password
	ok, err := security.VerifyPassword(u.PasswordHash, req.PasswordB64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("RegisterDevice:", "error", err)
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	d := NewDevice(u.ID, req.DeviceLabel, req.TPMPublicKey, req.PQPublicKey)
	deviceId, err := h.repo.CreateDevice(ctx, d)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("registerDevice:", "error", err)
		return
	}

	c.JSON(http.StatusCreated, registerDeviceResponse{
		DeviceID: deviceId,
		UserID:   u.ID,
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

	if req.UserID == "" || req.DeviceID == "" || req.PasswordB64 == "" ||
		req.MessageB64 == "" || req.TPMSignature == "" || req.PQSignature == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user_id, device_id, password, message, tpm_signature, pq_signature are required",
		})
		return
	}

	d, err := h.repo.GetDeviceByID(ctx, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("fullLogin:", "error", err)
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

	user, err := h.repo.GetUserByID(ctx, req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("fullLogin:", "error", err)
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	ok, err := security.VerifyPassword(user.PasswordHash, req.PasswordB64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("fullLogin:", "error", err)
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
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
	if msg.Purpose != constants.ClientLoginPurpose {
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

// RetrieveUser
// @BasePath /quantum-auth/v1
// @Summary      ME (email + password)
// @Description  Retrieve you user info using your credential. Used to add new device to your account.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        payload  body      meRequest   true  "ME"
// @Success      200      {object}  meResponse
// @Failure      400      {string}  string  "invalid input"
// @Failure      401      {string}  string  "unauthorized"
// @Failure      404      {string}  string  "user or device not found"
// @Router       /users/me [post]
func (h *Handler) RetrieveUser(c *gin.Context) {
	ctx := c.Request.Context()
	var req meRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Email == "" || req.PasswordB64 == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "email and password are required",
		})
		return
	}

	user, err := h.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("UpdateUserProfile:", "error", err)
		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	ok, err := security.VerifyPassword(user.PasswordHash, req.PasswordB64)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("retreiveUser:", "error", err)
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, meResponse{
		UserID: user.ID,
	})
}

// NewsletterSubscribe
// @BasePath /quantum-auth/v1
// @Summary      Subscribe to newsletter
// @Description  Creates or re-subscribes an email to the newsletter
// @Tags         newsletter
// @Accept       json
// @Produce      json
// @Param        payload  body      newsletterRequest true "Newsletter subscribe payload"
// @Success      201      {object}  newsletterResponse
// @Failure      400      {object}  map[string]string
// @Failure      500      {object}  map[string]string
// @Router       /newsletter/subscribe [post]
func (h *Handler) NewsletterSubscribe(c *gin.Context) {
	ctx := c.Request.Context()

	var req newsletterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	id, err := h.repo.SubscribeNewsletter(ctx, database.SubscribeNewsletterInput{Email: req.Email})
	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "subscribe failed"})
		log.Error("newsLetterSubscribe:", "error", err)
		return
	}

	c.JSON(http.StatusCreated, newsletterResponse{
		NewsletterID: id,
		Email:        req.Email,
		Subscribed:   true,
	})
}

// NewsletterUnsubscribe
// @BasePath /quantum-auth/v1
// @Summary      Unsubscribe from newsletter
// @Description  Marks an email as unsubscribed (soft unsubscribe)
// @Tags         newsletter
// @Accept       json
// @Produce      json
// @Param        payload  body      newsletterRequest true "Newsletter unsubscribe payload"
// @Success      200      {object}  newsletterResponse
// @Failure      400      {object}  map[string]string
// @Failure      500      {object}  map[string]string
// @Router       /newsletter/unsubscribe [post]
func (h *Handler) NewsletterUnsubscribe(c *gin.Context) {
	ctx := c.Request.Context()

	var req newsletterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

		return
	}

	id, err := h.repo.UnsubscribeNewsletter(ctx, database.UnsubscribeNewsletterInput{Email: req.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unsubscribe failed"})
		log.Error("newsLetterUnsubscribe:", "error", err)

		return
	}

	c.JSON(http.StatusOK, newsletterResponse{
		NewsletterID: id,
		Email:        req.Email,
		Subscribed:   false,
	})
}
