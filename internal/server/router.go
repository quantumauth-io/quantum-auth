package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	httpSwagger "github.com/swaggo/http-swagger"

	_ "github.com/Madeindreams/quantum-auth/docs" // swagger docs
)

func SetupRouter(store *Store) http.Handler {
	r := chi.NewRouter()

	api := &API{store: store}

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("ok"))
		if err != nil {
			return
		}
	})

	// swagger UI
	r.Get("/swagger/*", httpSwagger.WrapHandler)

	// users
	r.Post("/users/register", api.handleRegisterUser)

	// devices
	r.Post("/devices/register", api.handleRegisterDevice)

	// auth
	r.Post("/auth/challenge", api.handleAuthChallenge)
	r.Post("/auth/verify", api.handleAuthVerify)

	return r
}
