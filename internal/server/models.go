package server

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
}

func NewUser(email, passwordHash string) *User {
	return &User{
		ID:           uuid.NewString(),
		Email:        email,
		PasswordHash: passwordHash,
	}
}

type Device struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TPMPublicKey string    `json:"tpm_public_key"`
	PQPublicKey  string    `json:"pq_public_key"`
	CreatedAt    time.Time `json:"created_at"`
	IsRevoked    bool      `json:"is_revoked"`
}

func NewDevice(userID, tpmPublicKey, pqPublicKey string) *Device {
	return &Device{
		ID:           uuid.NewString(),
		UserID:       userID,
		TPMPublicKey: tpmPublicKey,
		PQPublicKey:  pqPublicKey,
		CreatedAt:    time.Now(),
		IsRevoked:    false,
	}
}

type Challenge struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewChallenge(deviceID string, ttl time.Duration) *Challenge {
	return &Challenge{
		ID:        uuid.NewString(),
		DeviceID:  deviceID,
		Nonce:     uuid.NewString(),
		ExpiresAt: time.Now().Add(ttl),
	}
}

type SignedMessage struct {
	ChallengeID string `json:"challenge_id"`
	DeviceID    string `json:"device_id"`
	Nonce       string `json:"nonce"`
	Purpose     string `json:"purpose"`
}
