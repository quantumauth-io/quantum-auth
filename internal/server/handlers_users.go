package server

import (
	"encoding/json"
	"net/http"
)

type API struct {
	store *Store
}

type registerUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerUserResponse struct {
	UserID string `json:"user_id"`
}

// Register a new user
// @Summary      Register user
// @Description  Creates a new user with email and password
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        payload  body      registerUserRequest  true  "User credentials"
// @Success      201      {object}  registerUserResponse
// @Failure      400      {string}  string  "invalid input"
// @Failure      409      {string}  string  "user already exists"
// @Router       /users/register [post]
func (api *API) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	var req registerUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}

	if existing := api.store.GetUserByEmail(req.Email); existing != nil {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	u := NewUser(req.Email, passwordHash)
	api.store.AddUser(u)

	resp := registerUserResponse{UserID: u.ID}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}
