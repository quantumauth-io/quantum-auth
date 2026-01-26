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
	"github.com/quantumauth-io/quantum-auth/internal/quantum/email"
	quantumhttp "github.com/quantumauth-io/quantum-auth/internal/quantum/qahttp"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/services"
	"github.com/quantumauth-io/quantum-go-utils/database"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

type Service struct {
	repo        *quantumdb.QuantumAuthRepository
	httpServer  *http.Server
	emailSender *email.SMTPSender
}

type SwaggerHTTPConfig struct {
	Port string
	Host string
}
type Config struct {
	GRPCServicePort   string
	DatabaseSettings  database.DatabaseSettings
	SMTPConfig        email.SMTPConfig
	SwaggerHTTPConfig SwaggerHTTPConfig
	DNSVerifierConfig services.AppVerifierConfig
}

//go:embed database/migrations/*.sql
var fs embed.FS

func NewQuantumAuthService(ctx context.Context, cfg *Config) (*Service, error) {
	cfg.DatabaseSettings.Password = os.Getenv("DB_PASS")
	cfg.DatabaseSettings.Host = os.Getenv("DB_HOST")
	cfg.DatabaseSettings.User = os.Getenv("DB_USER")
	cfg.SwaggerHTTPConfig.Port = os.Getenv("PORT")
	cfg.SMTPConfig.Password = os.Getenv("SMTP_TOKEN")
	cfg.SMTPConfig.Username = os.Getenv("SMTP_USER")
	cfg.DNSVerifierConfig.DNSServerAddr = os.Getenv("DNS_SERVER_ADDR")

	d, err := iofs.New(fs, "database/migrations")
	if err != nil {
		log.Error("New IOFS Err", "err", err)
		return nil, err
	}

	db, err := database.NewAuroraPGXDatabase(ctx, cfg.DatabaseSettings)
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
	sender := email.NewSMTPSender(cfg.SMTPConfig)

	engine := quantumhttp.NewRouter(ctx, repo, sender)

	httpSrv := &http.Server{
		Addr:    net.JoinHostPort(cfg.SwaggerHTTPConfig.Host, cfg.SwaggerHTTPConfig.Port),
		Handler: engine,
	}

	verifier := services.NewAppVerifierService(repo, cfg.DNSVerifierConfig)

	verifier.Start(ctx)

	return &Service{
		httpServer:  httpSrv,
		repo:        repo,
		emailSender: sender,
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
	log.Info("shutting down qa http server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("error during shutdown:", "error", err)
	}

}
