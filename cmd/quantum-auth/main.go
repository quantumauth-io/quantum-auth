package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Madeindreams/quantum-auth/internal/server"
)

// @title           Quantum Auth API
// @version         1.0
// @description     Experimental quantum-resistant, hardware-aware auth service.
// @host            localhost:1042
// @BasePath        /
func main() {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// instantiate service
	svc, err := server.NewQuantumAuthService(ctx)
	if err != nil {
		log.Fatal("failed to start quantum-auth service: ", err)
	}

	// run service
	go svc.Run(ctx)

	// graceful shutdown handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("shutting down due to signal")
	case <-ctx.Done():
		log.Println("shutting down due to context cancellation")
	}

	cancel()
	svc.Shutdown()
}
