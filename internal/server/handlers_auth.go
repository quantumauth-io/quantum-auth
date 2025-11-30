package server

import (
	"encoding/json"
	"net/http"
	"time"
)

type authChallengeRequest struct {
	DeviceID string `json:"device_id"`
}

type authChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Issue an authentication challenge for a device
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
func (api *API) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	var req authChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.DeviceID == "" {
		http.Error(w, "device_id is required", http.StatusBadRequest)
		return
	}

	d := api.store.GetDevice(req.DeviceID)
	if d == nil || d.IsRevoked {
		http.Error(w, "device not found or revoked", http.StatusNotFound)
		return
	}

	// 2-minute TTL for now
	ch := NewChallenge(d.ID, 2*time.Minute)
	api.store.AddChallenge(ch)

	resp := authChallengeResponse{
		ChallengeID: ch.ID,
		Nonce:       ch.Nonce,
		ExpiresAt:   ch.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

type authVerifyRequest struct {
	ChallengeID  string `json:"challenge_id"`
	DeviceID     string `json:"device_id"`
	Password     string `json:"password"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}

type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
}

func buildSignedMessage(ch *Challenge, deviceID string) ([]byte, error) {
	msg := SignedMessage{
		ChallengeID: ch.ID,
		DeviceID:    deviceID,
		Nonce:       ch.Nonce,
		Purpose:     "auth",
	}
	return json.Marshal(msg)
}

// Verify an authentication challenge response
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
func (api *API) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	var req authVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ChallengeID == "" || req.DeviceID == "" || req.Password == "" ||
		req.TPMSignature == "" || req.PQSignature == "" {
		http.Error(w, "challenge_id, device_id, password, tpm_signature, pq_signature are required", http.StatusBadRequest)
		return
	}

	ch := api.store.GetChallenge(req.ChallengeID)
	if ch == nil {
		http.Error(w, "challenge not found", http.StatusNotFound)
		return
	}

	if ch.DeviceID != req.DeviceID {
		http.Error(w, "device mismatch", http.StatusBadRequest)
		return
	}

	if time.Now().After(ch.ExpiresAt) {
		http.Error(w, "challenge expired", http.StatusBadRequest)
		return
	}

	d := api.store.GetDevice(req.DeviceID)
	if d == nil || d.IsRevoked {
		http.Error(w, "device not found or revoked", http.StatusNotFound)
		return
	}

	user := api.store.GetUserByID(d.UserID)
	if user == nil {
		http.Error(w, "user not found for device", http.StatusNotFound)
		return
	}

	// 1) verify password
	if !VerifyPassword(user.PasswordHash, req.Password) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(authVerifyResponse{
			Authenticated: false,
		})
		return
	}

	msgBytes, err := buildSignedMessage(ch, req.DeviceID)
	if err != nil {
		http.Error(w, "failed to build signed message", http.StatusInternalServerError)
		return
	}

	// 3) verify TPM signature (placeholder)
	if !verifyTPMSignature(d.TPMPublicKey, msgBytes, req.TPMSignature) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(authVerifyResponse{
			Authenticated: false,
		})
		return
	}

	// 4) verify PQ signature
	if !verifyPQSignature(d.PQPublicKey, []byte(msgBytes), req.PQSignature) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(authVerifyResponse{
			Authenticated: false,
		})
		return
	}

	// success: destroy challenge to prevent replay
	api.store.DeleteChallenge(ch.ID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(authVerifyResponse{
		Authenticated: true,
		UserID:        user.ID,
	})
}
