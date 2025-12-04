package quantumhttp

import (
	"context"

	quantumdb "github.com/Madeindreams/quantum-auth/internal/quantum/database"
	qamw "github.com/Madeindreams/quantum-auth/internal/quantum/transport/http/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/gin-gonic/gin"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/Madeindreams/quantum-auth/docs" // swagger docs
)

type Routes struct {
	h    *Handler
	repo *quantumdb.QuantumAuthRepository
	rdb  *redis.Client
}

// NewRoutes wires the HTTP handler with the QuantumAuthRepository and Redis.
func NewRoutes(ctx context.Context, repo *quantumdb.QuantumAuthRepository, rdb *redis.Client) *Routes {
	return &Routes{
		h:    NewHandler(ctx, repo, rdb),
		repo: repo,
		rdb:  rdb,
	}
}

// Register attaches all QuantumAuth routes to the given router group.
func (r *Routes) Register(api *gin.RouterGroup) {
	// ---- Health ----
	api.GET("/health", func(c *gin.Context) {
		c.String(200, "ok")
	})

	// ---- Swagger UI ----
	api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// ---- Users ----
	api.POST("/users/register", r.h.RegisterUser)

	// ---- Devices ----
	api.POST("/devices/register", r.h.RegisterDevice)

	// ---- Auth (challenge + verify) ----
	api.POST("/auth/challenge", r.h.AuthChallenge)
	api.POST("/auth/verify", r.h.AuthVerify)
	api.POST("/auth/full-login", r.h.FullLogin)

	// ---- Protected routes example (/api/secure-ping) ----
	secured := api.Group("/api")
	secured.Use(qamw.QuantumAuthMiddleware(qamw.Config{
		Repo:  r.repo,
		Redis: r.rdb,
		// NonceTTL: 5 * time.Minute, // optional: override default window
	}))
	secured.GET("/secure-ping", r.h.SecurePing)
}
