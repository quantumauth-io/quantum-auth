package server

import (
	"encoding/json"
	"net/http"
)

type registerDeviceRequest struct {
	UserEmail    string `json:"user_email"`
	TPMPublicKey string `json:"tpm_public_key"`
	PQPublicKey  string `json:"pq_public_key"`
}

type registerDeviceResponse struct {
	DeviceID string `json:"device_id"`
}

// Register a new device
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
func (api *API) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req registerDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.UserEmail == "" || req.TPMPublicKey == "" || req.PQPublicKey == "" {
		http.Error(w, "user_email, tpm_public_key and pq_public_key are required", http.StatusBadRequest)
		return
	}

	u := api.store.GetUserByEmail(req.UserEmail)
	if u == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	d := NewDevice(u.ID, req.TPMPublicKey, req.PQPublicKey)
	api.store.AddDevice(d)

	resp := registerDeviceResponse{DeviceID: d.ID}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}
