package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	qdb "github.com/quantumauth-io/quantum-auth/internal/quantum/database"
)

type fakeRepo struct {
	userByEmail        *qdb.User
	userByEmailErr     error
	userByID           *qdb.User
	userByIDErr        error
	deviceByID         *qdb.Device
	deviceByIDErr      error
	createUserID       string
	createUserErr      error
	createDevID        string
	createDevErr       error
	createChallengeID  string
	createChallengeErr error
	deleteChallengeErr error
}

func (f *fakeRepo) GetUserByEmail(ctx context.Context, email string) (*qdb.User, error) {
	return f.userByEmail, f.userByEmailErr
}

func (f *fakeRepo) CreateUser(ctx context.Context, in qdb.CreateUserInput) (string, error) {
	if f.createUserID == "" {
		f.createUserID = "user-123"
	}
	return f.createUserID, f.createUserErr
}

func (f *fakeRepo) GetUserByID(ctx context.Context, id string) (*qdb.User, error) {
	return f.userByID, f.userByIDErr
}

func (f *fakeRepo) GetDeviceByID(ctx context.Context, id string) (*qdb.Device, error) {
	return f.deviceByID, f.deviceByIDErr
}

func (f *fakeRepo) CreateDevice(ctx context.Context, in *qdb.CreateDeviceInput) (string, error) {
	if f.createDevID == "" {
		f.createDevID = "dev-123"
	}
	return f.createDevID, f.createDevErr
}

func (f *fakeRepo) CreateChallenge(ctx context.Context, in *qdb.CreateChallengeInput) (string, error) {
	if f.createChallengeID == "" {
		f.createChallengeID = "challenge-123"
	}
	return f.createChallengeID, f.createChallengeErr
}

func (f *fakeRepo) DeleteChallenge(ctx context.Context, id string) error {
	return f.deleteChallengeErr
}

func newTestRouter(repo QuantumAuthRepository) *gin.Engine {
	gin.SetMode(gin.TestMode)
	return NewRouter(context.Background(), repo)
}

func newTestHandler(repo QuantumAuthRepository) *Handler {
	return NewHandler(context.Background(), repo)
}

/* ---------------- router-level ---------------- */

func TestHealthRoute(t *testing.T) {
	r := newTestRouter(&fakeRepo{})

	req := httptest.NewRequest(http.MethodGet, "/quantum-auth/v1/health", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "ok" {
		t.Fatalf(`expected body "ok", got %q`, body)
	}
}

/* ---------------- RegisterUser ---------------- */

func TestRegisterUser_Success(t *testing.T) {
	repo := &fakeRepo{userByEmail: nil}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/users/register", h.RegisterUser)

	payload, _ := json.Marshal(SignupRequest{
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Password:  "secret",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/users/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["user_id"] == "" {
		t.Fatalf("expected user_id in response, got %#v", resp)
	}
}

func TestRegisterUser_EmailAlreadyExists(t *testing.T) {
	repo := &fakeRepo{
		userByEmail: &qdb.User{ID: "existing"},
	}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/users/register", h.RegisterUser)

	payload, _ := json.Marshal(SignupRequest{
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Password:  "secret",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/users/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestRegisterUser_CreateUserError(t *testing.T) {
	repo := &fakeRepo{
		userByEmail:   nil,
		createUserErr: errors.New("db error"),
	}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/users/register", h.RegisterUser)

	payload, _ := json.Marshal(SignupRequest{
		Email:     "test@example.com",
		Username:  "testuser",
		FirstName: "Test",
		LastName:  "User",
		Password:  "secret",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/users/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

/* ---------------- RegisterDevice ---------------- */

func TestRegisterDevice_UserNotFound(t *testing.T) {
	repo := &fakeRepo{userByID: nil}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/devices/register", h.RegisterDevice)

	payload, _ := json.Marshal(registerDeviceRequest{
		UserId:       "user-1",
		DeviceLabel:  "laptop",
		TPMPublicKey: "tpm-key",
		PQPublicKey:  "pq-key",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/devices/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestRegisterDevice_Success(t *testing.T) {
	repo := &fakeRepo{
		userByID: &qdb.User{ID: "user-1"},
	}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/devices/register", h.RegisterDevice)

	payload, _ := json.Marshal(registerDeviceRequest{
		UserId:       "user-1",
		DeviceLabel:  "laptop",
		TPMPublicKey: "tpm-key",
		PQPublicKey:  "pq-key",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/devices/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["device_id"] == "" {
		t.Fatalf("expected device_id in response, got %#v", resp)
	}
}

func TestRegisterDevice_GetUserError(t *testing.T) {
	repo := &fakeRepo{
		userByIDErr: errors.New("db error"),
	}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/devices/register", h.RegisterDevice)

	payload, _ := json.Marshal(registerDeviceRequest{
		UserId:       "user-1",
		DeviceLabel:  "laptop",
		TPMPublicKey: "tpm-key",
		PQPublicKey:  "pq-key",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/devices/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

/* ---------------- AuthChallenge ---------------- */

func TestAuthChallenge_MissingDeviceID(t *testing.T) {
	repo := &fakeRepo{}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/challenge", h.AuthChallenge)

	payload, _ := json.Marshal(authChallengeRequest{
		DeviceID: "",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/challenge", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthChallenge_DeviceNotFound(t *testing.T) {
	repo := &fakeRepo{deviceByID: nil}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/challenge", h.AuthChallenge)

	payload, _ := json.Marshal(authChallengeRequest{
		DeviceID: "dev-1",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/challenge", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthChallenge_GetDeviceError(t *testing.T) {
	repo := &fakeRepo{deviceByIDErr: errors.New("db error")}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/challenge", h.AuthChallenge)

	payload, _ := json.Marshal(authChallengeRequest{
		DeviceID: "dev-1",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/challenge", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthChallenge_Success(t *testing.T) {
	repo := &fakeRepo{
		deviceByID: &qdb.Device{ID: "dev-1"},
	}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/challenge", h.AuthChallenge)

	payload, _ := json.Marshal(authChallengeRequest{
		DeviceID: "dev-1",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/challenge", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

/* ---------------- AuthVerify (validation branches) ---------------- */

func TestAuthVerify_MissingAuthorizationHeader(t *testing.T) {
	repo := &fakeRepo{}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/verify", h.AuthVerify)

	headers := map[string]string{
		"host":                        "localhost:1042",
		"x-quantumauth-canonical-b64": base64.StdEncoding.EncodeToString([]byte("dummy")),
	}

	payload, _ := json.Marshal(authVerifyRequest{
		Method:  "GET",
		Path:    "/foo",
		Headers: headers,
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/verify", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthVerify_InvalidCanonicalBase64(t *testing.T) {
	repo := &fakeRepo{}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/verify", h.AuthVerify)

	headers := map[string]string{
		"host":                        "localhost:1042",
		"authorization":               `QuantumAuth challenge="c1",sig_tpm="t",sig_pq="p"`,
		"x-quantumauth-canonical-b64": "%%%not-base64%%%",
	}

	payload, _ := json.Marshal(authVerifyRequest{
		Method:  "GET",
		Path:    "/foo",
		Headers: headers,
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/verify", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

/* ---------------- FullLogin (early branches) ---------------- */

func TestFullLogin_MissingFields(t *testing.T) {
	repo := &fakeRepo{}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/full-login", h.FullLogin)

	payload, _ := json.Marshal(fullLoginRequest{})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/full-login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestFullLogin_DeviceNotFound(t *testing.T) {
	repo := &fakeRepo{deviceByID: nil}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	_, r := gin.CreateTestContext(rec)

	r.POST("/quantum-auth/v1/auth/full-login", h.FullLogin)

	payload, _ := json.Marshal(fullLoginRequest{
		UserID:       "user-1",
		DeviceID:     "dev-1",
		Password:     "secret",
		MessageB64:   base64.StdEncoding.EncodeToString([]byte(`{"user_id":"user-1","device_id":"dev-1","purpose":"client-login","ts":123}`)),
		TPMSignature: "t-sig",
		PQSignature:  "p-sig",
	})

	req, _ := http.NewRequest(http.MethodPost, "/quantum-auth/v1/auth/full-login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d, body=%s", rec.Code, rec.Body.String())
	}
}

/* ---------------- SecurePing ---------------- */

func TestSecurePing_UsesContextValues(t *testing.T) {
	repo := &fakeRepo{}
	h := newTestHandler(repo)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	c.Set("userID", "user-abc")
	c.Set("deviceID", "dev-xyz")

	h.SecurePing(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if resp["user_id"] != "user-abc" || resp["device_id"] != "dev-xyz" {
		t.Fatalf("unexpected body: %#v", resp)
	}
}

/* ---------------- parseQuantumAuthHeader ---------------- */

func TestParseQuantumAuthHeader_Valid(t *testing.T) {
	h := `QuantumAuth challenge="abc", sig_tpm="t", sig_pq="p"`
	fields, err := parseQuantumAuthHeader(h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fields["challenge"] != "abc" || fields["sig_tpm"] != "t" || fields["sig_pq"] != "p" {
		t.Fatalf("unexpected fields: %#v", fields)
	}
}

func TestParseQuantumAuthHeader_InvalidScheme(t *testing.T) {
	h := `Bearer something`
	_, err := parseQuantumAuthHeader(h)
	if err == nil {
		t.Fatalf("expected error for invalid scheme")
	}
}
