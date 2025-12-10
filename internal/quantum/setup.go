package quantum

import (
	"context"
	"embed"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	quantumdb "github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	quantumhttp "github.com/quantumauth-io/quantum-auth/internal/quantum/http"
	"github.com/quantumauth-io/quantum-go-utils/database"
	"github.com/quantumauth-io/quantum-go-utils/log"
	rdb "github.com/quantumauth-io/quantum-go-utils/redis"
)

type Service struct {
	repo       *quantumdb.QuantumAuthRepository
	httpServer *http.Server
}

type SwaggerHTTPConfig struct {
	Port string
	Host string
}
type Config struct {
	GRPCServicePort   string
	DatabaseSettings  database.DatabaseSettings
	SwaggerHTTPConfig SwaggerHTTPConfig
	RedisConfig       rdb.Config
}

const ApiBase = "/quantum-auth/v1"

//go:embed database/migrations/*.sql
var fs embed.FS

func NewQuantumAuthService(ctx context.Context, cfg *Config) (*Service, error) {
	cfg.DatabaseSettings.Password = os.Getenv("DB_PASS")
	cfg.DatabaseSettings.Host = os.Getenv("DB_HOST")

	d, err := iofs.New(fs, "database/migrations")
	if err != nil {
		log.Error("New IOFS Err", "err", err)
		return nil, err
	}

	db, err := database.NewCockroachPGXDatabase(ctx, cfg.DatabaseSettings)
	if err != nil {
		log.Error("Failed to create database instance", "err", err)
		return nil, err
	}

	err = db.MigrateWithIOFS(ctx, d)
	if err != nil {
		log.Error("Migrate and Get Database With IOFS Err", "err", err)
		return nil, err
	}

	repo := quantumdb.NewRepository(db)

	engine := quantumhttp.NewRouter(ctx, repo)

	httpSrv := &http.Server{
		Addr:    net.JoinHostPort(cfg.SwaggerHTTPConfig.Host, cfg.SwaggerHTTPConfig.Port),
		Handler: engine,
	}

	return &Service{
		httpServer: httpSrv,
		repo:       repo,
	}, nil
}

func (s *Service) Run(ctx context.Context) {
	log.Info("quantum service starting on", "address", s.httpServer.Addr)

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server:", "error", err)
		}
	}()

	<-ctx.Done()
}

func (s *Service) Shutdown() {
	log.Info("shutting down http server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("error during shutdown:", "error", err)
	}

}
