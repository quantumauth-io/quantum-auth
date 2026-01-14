package http

import (
	"encoding/json"
	"time"
)

// ---------- Requests / Responses ----------

type authChallengeRequest struct {
	DeviceID string `json:"device_id" binding:"required"` // add uuid/len rule if you have one
}

type authChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       int64     `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type authVerifyRequest struct {
	Method    string            `json:"method" binding:"required,oneof=GET POST PUT PATCH DELETE"`
	Path      string            `json:"path" binding:"required"`
	Headers   map[string]string `json:"headers" binding:"required"`
	Encrypted json.RawMessage   `json:"encrypted" binding:"required"` // must be present + non-empty
}

// Response: omitempty is good here to avoid leaking user_id when not authenticated.
type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
}

// ---------- Domain models ----------

type Challenge struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Device struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TPMPublicKey string    `json:"tpm_public_key"`
	PQPublicKey  string    `json:"pq_public_key"`
	CreatedAt    time.Time `json:"created_at"`
	IsRevoked    bool      `json:"is_revoked"`
}

// Signed payload: do NOT use omitempty anywhere.
type SignedMessage struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	DeviceID    string `json:"device_id" binding:"required"`
	Nonce       int64  `json:"nonce" binding:"required"`
	Purpose     string `json:"purpose" binding:"required,oneof=login secure_ping verify_request"`
}

// ---------- Device registration ----------

// Option A (recommended): keep this endpoint purely password-backed, no omitempty.
type registerDeviceRequest struct {
	UserEmail    string `json:"user_email" binding:"required,email"`
	PasswordB64  string `json:"password_b64" binding:"required,min=8"`
	DeviceLabel  string `json:"device_label" binding:"required,min=1,max=64"`
	TPMPublicKey string `json:"tpm_public_key" binding:"required,min=32"` // adjust min to your encoding
	PQPublicKey  string `json:"pq_public_key" binding:"required,min=32"`
}

type registerDeviceResponse struct {
	DeviceID string `json:"device_id"`
}

// ---------- Signup / login ----------

type SignupRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Username    string `json:"username" binding:"omitempty,min=3,max=32"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
	FirstName   string `json:"firstName" binding:"omitempty,max=64"`
	LastName    string `json:"lastName" binding:"omitempty,max=64"`
}

// ---- OLD

type LoginRequest struct {
	Email       string `json:"email" binding:"required,email"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ChangePasswordRequest struct {
	Current string `json:"current" binding:"required,min=8"`
	New     string `json:"new" binding:"required,min=8"`
}

type RequestResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
}

type meRequest struct {
	Email       string `json:"email" binding:"required,email"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
}

type meResponse struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

type fullLoginRequest struct {
	UserID       string `json:"user_id" binding:"required"`
	DeviceID     string `json:"device_id" binding:"required"`
	PasswordB64  string `json:"password_b64" binding:"required,min=8"`
	MessageB64   string `json:"message_b64" binding:"omitempty"`
	TPMSignature string `json:"tpm_signature" binding:"omitempty"`
	PQSignature  string `json:"pq_signature" binding:"omitempty"`
}

type fullLoginResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
}

type newsletterRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type newsletterResponse struct {
	NewsletterID string `json:"newsletter_id,omitempty"`
	Email        string `json:"email"`
	Subscribed   bool   `json:"subscribed"`
}

type SecurePingResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
}
