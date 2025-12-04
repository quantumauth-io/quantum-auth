package quantumhttp

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
	UserId       string `json:"user_Id"`
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
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// ---- OLD

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
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
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
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
	Password     string `json:"password"`
	Message      string `json:"message"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}

type fullLoginResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id"`
	DeviceID      string `json:"device_id"`
}
