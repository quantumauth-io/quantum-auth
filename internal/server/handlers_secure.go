package server

import (
	"encoding/json"
	"net/http"
)

type securePingResponse struct {
	OK       bool   `json:"ok"`
	UserID   string `json:"user_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}

func (a *API) handleSecurePing(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userID").(string)
	deviceID, _ := r.Context().Value("deviceID").(string)

	resp := securePingResponse{
		OK:       true,
		UserID:   userID,
		DeviceID: deviceID,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
