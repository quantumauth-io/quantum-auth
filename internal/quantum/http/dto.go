package http

import (
	"encoding/json"
	"time"
)

type authChallengeRequest struct {
	DeviceID string `json:"device_id"`
}

type authChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       int64     `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Challenge struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
}

type registerDeviceRequest struct {
	UserEmail    string `json:"user_email,omitempty"`
	PasswordB64  string `json:"password_b64,omitempty"`
	DeviceLabel  string `json:"device_label"`
	TPMPublicKey string `json:"tpm_public_key"`
	PQPublicKey  string `json:"pq_public_key"`
}

type registerDeviceResponse struct {
	DeviceID string `json:"device_id"`
}

type Device struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TPMPublicKey string    `json:"tpm_public_key"`
	PQPublicKey  string    `json:"pq_public_key"`
	CreatedAt    time.Time `json:"created_at"`
	IsRevoked    bool      `json:"is_revoked"`
}

type authVerifyRequest struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Encrypted json.RawMessage   `json:"encrypted"` // keep for future decryption
}

type SignedMessage struct {
	ChallengeID string `json:"challenge_id"`
	DeviceID    string `json:"device_id"`
	Nonce       int64  `json:"nonce"`
	Purpose     string `json:"purpose"`
}

type SecurePingResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
}

type SignupRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Username    string `json:"username"`
	PasswordB64 string `json:"password_b64"`
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
}

// ---- OLD

type LoginRequest struct {
	Email       string `json:"email" binding:"required,email"`
	PasswordB64 string `json:"password_b64" binding:"required"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ChangePasswordRequest struct {
	Current string `json:"current" binding:"required"`
	New     string `json:"new" binding:"required,min=8"`
}

type RequestResetRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
}

type MeResponse struct {
	UserID    string `json:"userId"`
	Email     string `json:"email"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

type fullLoginRequest struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	PasswordB64  string `json:"password_b64"`
	MessageB64   string `json:"message_b64"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}

type fullLoginResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id"`
	DeviceID      string `json:"device_id"`
}

type newsletterRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type newsletterResponse struct {
	NewsletterID string `json:"newsletter_id,omitempty"`
	Email        string `json:"email"`
	Subscribed   bool   `json:"subscribed"`
}
