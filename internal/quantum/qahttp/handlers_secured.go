package qahttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	qagin "github.com/quantumauth-io/go-quantumauth-mw/gin"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/email"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"
)

type SecureHandlers struct {
	ctx         context.Context
	repo        *database.QuantumAuthRepository
	emailSender *email.SMTPSender
}

func NewSecureHandler(ctx context.Context, repo *database.QuantumAuthRepository, emailSender *email.SMTPSender) *SecureHandlers {
	return &SecureHandlers{
		ctx:         ctx,
		repo:        repo,
		emailSender: emailSender,
	}
}

// RetrieveUserProfile
// @BasePath     /quantum-auth/v1/secured
// @Summary      Get current user profile
// @Description  Retrieve the authenticated user's profile.
// @Tags         user profile
// @Accept       json
// @Produce      json
// @Success      200  {object}  meResponse
// @Failure      401  {string}  string  "unauthorized"
// @Failure      404  {string}  string  "user not found"
// @Router       /qa/users/me [get]
func (sh *SecureHandlers) RetrieveUserProfile(c *gin.Context) {
	ctx := c.Request.Context()

	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	user, err := sh.repo.GetUserByID(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("getUserByID:", "error", err)

		return
	}
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})

		return
	}

	c.JSON(http.StatusOK, meResponse{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		CreatedAt: user.CreatedAt,
	})
}

// UpdateUserProfile
// @BasePath     /quantum-auth/v1/secured
// @Summary      Update current user profile
// @Description  Partially update the authenticated user's profile. Only provided fields are updated.
// @Tags         user profile
// @Accept       json
// @Produce      json
// @Param        payload  body      updateMeRequest  true  "User profile fields to update"
// @Success      200      {object}  meResponse
// @Failure      400      {string}  string  "invalid input"
// @Failure      401      {string}  string  "unauthorized"
// @Failure      409      {string}  string  "email or username already exists"
// @Failure      500      {string}  string  "internal server error"
// @Router       /qa/users/me [patch]
func (sh *SecureHandlers) UpdateUserProfile(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	var req updateMeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})

		return
	}

	// Optional: reject empty patch
	if req.Email == nil && req.Username == nil && req.FirstName == nil && req.LastName == nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "no fields to update"})

		return
	}

	// Validate only provided fields
	if req.Email != nil {
		userEmail := strings.TrimSpace(*req.Email)
		if userEmail == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "email cannot be empty"})

			return
		}
		*req.Email = userEmail
	}

	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		if username == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "username cannot be empty"})

			return
		}
		*req.Username = username
	}

	if req.FirstName != nil {
		first := strings.TrimSpace(*req.FirstName)
		*req.FirstName = first
	}

	if req.LastName != nil {
		last := strings.TrimSpace(*req.LastName)
		*req.LastName = last
	}

	updated, err := sh.repo.UpdateUserByID(c, userID, database.UpdateUserByIDInput{
		Email:     req.Email,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Error("updateUserProfile:", "error", err)

		return
	}

	c.JSON(http.StatusOK, meResponse{
		UserID:    updated.ID,
		Email:     updated.Email,
		Username:  updated.Username,
		FirstName: updated.FirstName,
		LastName:  updated.LastName,
		CreatedAt: updated.CreatedAt,
	})
}

// ListMyDevices
// @BasePath     /quantum-auth/v1/secured
// @Summary      List devices for current user
// @Description  Retrieve all devices registered to the authenticated user.
// @Tags         device profile
// @Accept       json
// @Produce      json
// @Success      200  {array}   deviceResponse
// @Failure      401  {string}  string  "unauthorized"
// @Failure      500  {string}  string  "internal server error"
// @Router       /qa/devices [get]
func (sh *SecureHandlers) ListMyDevices(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	devs, err := sh.repo.GetDevicesByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		log.Error("listMyDevice:", "error", err)

		return
	}

	out := make([]deviceResponse, 0, len(devs))
	for _, d := range devs {
		out = append(out, deviceResponse{
			DeviceID:     d.ID,
			UserID:       d.UserID,
			DeviceLabel:  d.DeviceLabel,
			TPMPublicKey: d.TPMPublicKey,
			PQPublicKey:  d.PQPublicKey,
			CreatedAt:    d.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, out)
}

// UpdateMyDevice
// @BasePath     /quantum-auth/v1/secured
// @Summary      Update a device
// @Description  Partially update a device that belongs to the authenticated user. Currently supports updating device_label.
// @Tags         device profile
// @Accept       json
// @Produce      json
// @Param        device_id  path      string               true  "Device ID"
// @Param        payload    body      updateDeviceRequest  true  "Device fields to update"
// @Success      200        {object}  deviceResponse
// @Failure      400        {string}  string  "invalid input"
// @Failure      401        {string}  string  "unauthorized"
// @Failure      403        {string}  string  "forbidden"
// @Failure      404        {string}  string  "device not found"
// @Failure      500        {string}  string  "internal server error"
// @Router       /qa/devices/{device_id} [patch]
func (sh *SecureHandlers) UpdateMyDevice(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	deviceID := c.Param("device_id")
	if strings.TrimSpace(deviceID) == "" {
		c.JSON(http.StatusBadRequest, "invalid device_id input")

		return
	}

	var req updateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, "invalid request input")

		return
	}

	if req.DeviceLabel == nil {
		c.JSON(http.StatusBadRequest, "no fields to update")

		return
	}

	if req.DeviceLabel != nil {
		v := strings.TrimSpace(*req.DeviceLabel)
		if v == "" {
			c.JSON(http.StatusBadRequest, "device_label cannot be empty")

			return
		}
		*req.DeviceLabel = v
	}

	d, err := sh.repo.GetDeviceByID(c.Request.Context(), deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, "device not found")

		return
	}
	if d.UserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")

		return
	}

	updated, err := sh.repo.UpdateDeviceByID(c.Request.Context(), deviceID, database.UpdateDeviceByIDInput{
		DeviceLabel: req.DeviceLabel,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		log.Error("updateMyDevice:", "error", err)

		return
	}

	c.JSON(http.StatusOK, deviceResponse{
		DeviceID:     updated.ID,
		UserID:       updated.UserID,
		DeviceLabel:  updated.DeviceLabel,
		TPMPublicKey: updated.TPMPublicKey,
		PQPublicKey:  updated.PQPublicKey,
		CreatedAt:    updated.CreatedAt,
	})
}

// CreateApp
// @BasePath     /quantum-auth/v1/secured
// @Summary      Create a developer app
// @Description  Create an app and return DNS TXT verification instructions.
// @Tags         developer apps
// @Accept       json
// @Produce      json
// @Param        payload  body      createAppRequest  true  "Create app"
// @Success      201      {object}  createAppResponse
// @Failure      400      {string}  string  "invalid input"
// @Failure      401      {string}  string  "unauthorized"
// @Failure      409      {string}  string  "domain already exists"
// @Failure      500      {string}  string  "internal server error"
// @Router       /qa/apps [post]
func (sh *SecureHandlers) CreateApp(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	var req createAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, "invalid input")

		return
	}

	name := strings.TrimSpace(req.Name)
	desc := strings.TrimSpace(req.Description)
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	backendHost := requests.NormalizeBackendHost(req.BackendHost)

	if name == "" || domain == "" || backendHost == "" {
		c.JSON(http.StatusBadRequest, "invalid input")

		return
	}

	var pqKey []byte
	if req.PQPublicKeyB64 != nil {
		b, err := decodePQKeyB64(*req.PQPublicKeyB64)
		if err != nil {
			c.JSON(http.StatusBadRequest, "invalid pq public key")

			return
		}
		pqKey = b
	}

	token, err := generateVerificationToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		log.Error("createApp:", "error", err)

		return
	}

	app, err := sh.repo.CreateApp(c.Request.Context(), database.CreateAppInput{
		OwnerUserID:       userID,
		Name:              name,
		Description:       desc,
		Domain:            domain,
		BackendHost:       backendHost,
		Tier:              constants.QAFreeTier,
		VerificationToken: token,
		PQPublicKey:       pqKey,
	})
	if err != nil {
		if database.IsUniqueViolation(err) {
			c.JSON(http.StatusConflict, "domain already exists")
			return
		}
		c.JSON(http.StatusInternalServerError, "internal server error")
		log.Error("createApp:", "error", err)
		return
	}

	tokenValue := constants.QADNSRecordValuePrefix + app.VerificationToken

	resp := createAppResponse{App: toAppResponse(app)}
	resp.DNS.Records = append(resp.DNS.Records,
		DNSRecord{
			Name:  constants.QADNSRecordName + app.Domain,
			Type:  constants.QADNSRecordType,
			Value: tokenValue,
		},
		DNSRecord{
			Name:  constants.QADNSRecordName + requests.NormalizeBackendHost(app.BackendHost),
			Type:  constants.QADNSRecordType,
			Value: tokenValue,
		},
	)

	c.JSON(http.StatusCreated, resp)
}

// ListMyApps
// @BasePath     /quantum-auth/v1/secured
// @Summary      List my apps
// @Description  List all apps owned by the authenticated user.
// @Tags         developer apps
// @Produce      json
// @Success      200  {array}   appResponse
// @Failure      401  {string}  string  "unauthorized"
// @Failure      500  {string}  string  "internal server error"
// @Router       /qa/apps [get]
func (sh *SecureHandlers) ListMyApps(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	apps, err := sh.repo.GetAppsByUserID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "internal server error")
		log.Error("listMyApps:", "error", err)

		return
	}

	out := make([]appResponse, 0, len(apps))
	for _, a := range apps {
		out = append(out, toAppResponse(a))
	}

	c.JSON(http.StatusOK, out)
}

// GetMyApp
// @BasePath     /quantum-auth/v1/secured
// @Summary      Get my app
// @Description  Get an app by id (must be owned by the authenticated user).
// @Tags         developer apps
// @Produce      json
// @Param        app_id  path      string  true  "App ID"
// @Success      200     {object}  appResponse
// @Failure      401     {string}  string  "unauthorized"
// @Failure      403     {string}  string  "forbidden"
// @Failure      404     {string}  string  "not found"
// @Failure      500     {string}  string  "internal server error"
// @Router       /qa/apps/{app_id} [get]
func (sh *SecureHandlers) GetMyApp(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	appID := strings.TrimSpace(c.Param("app_id"))
	if appID == "" {
		c.JSON(http.StatusNotFound, "not found")

		return
	}

	app, err := sh.repo.GetAppByID(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")

		return
	}
	if app.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")

		return
	}

	c.JSON(http.StatusOK, toAppResponse(app))
}

// UpdateMyApp
// @BasePath     /quantum-auth/v1/secured
// @Summary      Update my app
// @Description  Partially update an app. Changing domain resets verification and issues a new token.
// @Tags         developer apps
// @Accept       json
// @Produce      json
// @Param        app_id    path      string            true  "App ID"
// @Param        payload   body      updateAppRequest  true  "Update app"
// @Success      200       {object}  createAppResponse
// @Failure      400       {string}  string  "invalid input"
// @Failure      401       {string}  string  "unauthorized"
// @Failure      403       {string}  string  "forbidden"
// @Failure      404       {string}  string  "not found"
// @Failure      409       {string}  string  "domain already exists"
// @Failure      500       {string}  string  "internal server error"
// @Router       /qa/apps/{app_id} [patch]
func (sh *SecureHandlers) UpdateMyApp(c *gin.Context) {
	userID, ok := qagin.UserID(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	appID := strings.TrimSpace(c.Param("app_id"))
	if appID == "" {
		c.JSON(http.StatusNotFound, "not found")

		return
	}

	existing, err := sh.repo.GetAppByID(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, "not found")

		return
	}
	if existing.OwnerUserID != userID {
		c.JSON(http.StatusForbidden, "forbidden")

		return
	}

	var req updateAppRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, "invalid input")

		return
	}

	var normalizedHost string
	if (req.BackendHost) != nil {
		normalizedHost = requests.NormalizeOptionalBackendHost(req.BackendHost)
		if normalizedHost == "" {
			c.JSON(http.StatusBadRequest, "invalid backend host")
			return
		}
	}

	in := database.UpdateAppByIDInput{
		Name:        trimPtr(req.Name),
		Description: trimPtr(req.Description),
		Tier:        trimPtr(req.Tier),
	}

	if req.PQPublicKeyB64 != nil {
		b, err := decodePQKeyB64(*req.PQPublicKeyB64)
		if err != nil {
			c.JSON(http.StatusBadRequest, "invalid pq public key")

			return
		}
		in.PQPublicKey = &b
	}

	resetNeeded := false

	// DOMAIN (already like this)
	if req.Domain != nil {
		d := strings.ToLower(strings.TrimSpace(*req.Domain))
		if d == "" {
			c.JSON(http.StatusBadRequest, "invalid domain")
			return
		}
		in.Domain = &d

		if d != existing.Domain {
			resetNeeded = true
		}
	}

	// BACKEND HOST (same pattern)
	if req.BackendHost != nil {
		h := requests.NormalizeBackendHost(strings.TrimSpace(*req.BackendHost))
		if h == "" {
			c.JSON(http.StatusBadRequest, "invalid backend host")
			return
		}

		in.BackendHost = &h

		existingH := requests.NormalizeBackendHost(existing.BackendHost)
		if existingH == "" {
			resetNeeded = true
		} else if h != existingH {
			resetNeeded = true
		}
	}

	// If either changed, reset verification + new token
	if resetNeeded {
		in.ResetVerification = true

		newToken, err := generateVerificationToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, "internal server error")
			log.Error("updateMyApp", "error", err)
			return
		}
		in.NewToken = &newToken
	}

	updated, err := sh.repo.UpdateAppByID(c.Request.Context(), appID, in)
	if err != nil {
		if database.IsUniqueViolation(err) {
			c.JSON(http.StatusConflict, "domain already exists")

			return
		}
		c.JSON(http.StatusInternalServerError, "internal server error")
		log.Error("UpdateMyApp:", "error", err)
		return
	}

	tokenValue := constants.QADNSRecordValuePrefix + updated.VerificationToken

	resp := createAppResponse{App: toAppResponse(updated)}
	resp.DNS.Records = append(resp.DNS.Records,
		DNSRecord{
			Name:  constants.QADNSRecordName + updated.Domain,
			Type:  constants.QADNSRecordType,
			Value: tokenValue,
		},
		DNSRecord{
			Name:  constants.QADNSRecordName + requests.NormalizeBackendHost(updated.BackendHost),
			Type:  constants.QADNSRecordType,
			Value: tokenValue,
		},
	)

	c.JSON(http.StatusOK, resp)
}
