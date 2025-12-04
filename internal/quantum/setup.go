package quantum

import (
	"context"
	"embed"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	quantumdb "github.com/Madeindreams/quantum-auth/internal/quantum/database"
	quantumhttp "github.com/Madeindreams/quantum-auth/internal/quantum/modules/oauth/http"
	"github.com/gin-gonic/gin"

	"github.com/Madeindreams/quantum-go-utils/database"
	"github.com/Madeindreams/quantum-go-utils/log"
	rdb "github.com/Madeindreams/quantum-go-utils/redis"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/redis/go-redis/v9"
)

type Service struct {
	rdb        *redis.Client
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

	redisDB, err := rdb.NewClient(ctx, rdb.Config{
		Host:     cfg.RedisConfig.Host,
		Port:     cfg.RedisConfig.Port,
		Password: os.Getenv("REDIS_PASSWORD"),
	})

	if err != nil {
		log.Error("Failed to create redis instance", "err", err)
		return nil, err
	}

	repo := quantumdb.NewRepository(db)

	r := gin.Default()
	_ = r.SetTrustedProxies(nil)

	routes := quantumhttp.NewRoutes(ctx, repo, redisDB)
	routes.Register(r.Group(ApiBase))

	engine := r

	httpSrv := &http.Server{
		Addr:    net.JoinHostPort(cfg.SwaggerHTTPConfig.Host, cfg.SwaggerHTTPConfig.Port),
		Handler: engine,
	}

	return &Service{
		httpServer: httpSrv,
		rdb:        redisDB,
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
