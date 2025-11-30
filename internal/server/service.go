package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

type QuantumAuthService struct {
	httpServer *http.Server
	store      *Store
}

func NewQuantumAuthService(ctx context.Context) (*QuantumAuthService, error) {

	store := NewStore()

	mux := SetupRouter(store)

	httpSrv := &http.Server{
		Addr:    ":1042",
		Handler: mux,
	}

	return &QuantumAuthService{
		httpServer: httpSrv,
		store:      store,
	}, nil
}

func (s *QuantumAuthService) Run(ctx context.Context) {
	log.Println("quantum-auth service starting on :1042")

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("server error: ", err)
		}
	}()

	<-ctx.Done()
}

func (s *QuantumAuthService) Shutdown() {
	log.Println("shutting down http server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Println("error during shutdown:", err)
	}
}
