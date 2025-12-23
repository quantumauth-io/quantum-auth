package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/quantumauth-io/quantum-auth/internal/quantum"
	"github.com/quantumauth-io/quantum-go-utils/config"
)

// @title           QuantumAuth API
// @version         1.0
// @description     Experimental quantum-resistant, hardware-aware auth service.
// @BasePath        /
func main() {

	cfg, err := config.ParseConfig[quantum.Config]([]string{"./config/", "./cmd/quantum-auth/config/"})
	if err != nil {
		log.Fatal("failed to parse config", "error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// instantiate service
	svc, err := quantum.NewQuantumAuthService(ctx, cfg)
	if err != nil {
		log.Fatal("failed to start quantum service: ", err)
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
