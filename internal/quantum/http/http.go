package http

import (
	"context"

	"github.com/gin-gonic/gin"
	_ "github.com/quantumauth-io/quantum-auth/docs"
	qamw "github.com/quantumauth-io/quantum-auth/internal/quantum/transport/http/middleware"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

const ApiBase = "/quantum-auth/v1"

type Routes struct {
	h    *Handler
	repo QuantumAuthRepository
}

// NewRoutes builds your main API route registrar
func NewRoutes(ctx context.Context, repo QuantumAuthRepository) *Routes {
	return &Routes{
		h:    NewHandler(ctx, repo), // ← your handler constructor
		repo: repo,
	}
}

// NewRouter creates the Gin engine + registers ALL routes
func NewRouter(ctx context.Context, repo QuantumAuthRepository) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	_ = r.SetTrustedProxies(nil)

	api := r.Group(ApiBase)

	// ---- MAIN QuantumAuth API ----
	mainRoutes := NewRoutes(ctx, repo)
	mainRoutes.Register(api)

	return r
}

func (r *Routes) Register(api *gin.RouterGroup) {
	// ---- Health ----
	api.GET("/health", func(c *gin.Context) {
		c.String(200, "ok")
	})

	// ---- Swagger ----
	api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// ---- Users ----
	api.POST("/users/register", r.h.RegisterUser)

	// ---- Devices ----
	api.POST("/devices/register", r.h.RegisterDevice)

	// ---- Auth ----
	api.POST("/auth/challenge", r.h.AuthChallenge)
	api.POST("/auth/verify", r.h.AuthVerify)
	api.POST("/auth/full-login", r.h.FullLogin)

	// ---- Protected routes ----
	secured := api.Group("/api")
	secured.Use(qamw.QuantumAuthMiddleware(qamw.Config{
		Repo: r.repo,
	}))
	secured.GET("/secure-ping", r.h.SecurePing)
}
