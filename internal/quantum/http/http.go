package http

import (
	"context"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/quantumauth-io/quantum-auth/docs"
	_ "github.com/quantumauth-io/quantum-auth/docs"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/email"
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
func NewRoutes(ctx context.Context, repo QuantumAuthRepository, emailSender *email.SMTPSender) *Routes {
	return &Routes{
		h:    NewHandler(ctx, repo, emailSender),
		repo: repo,
	}
}

// NewRouter creates the Gin engine + registers ALL routes
func NewRouter(ctx context.Context, repo QuantumAuthRepository, emailSender *email.SMTPSender) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	_ = r.SetTrustedProxies(nil)

	// ---- CORS (must be BEFORE routes) ----
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:4321",
			"http://127.0.0.1:4321",
			"https://dev.quantumauth.io",
			"https://quantumauth.io",
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	api := r.Group(ApiBase)

	// ---- MAIN QuantumAuth API ----
	mainRoutes := NewRoutes(ctx, repo, emailSender)
	mainRoutes.Register(api)

	return r
}

func (r *Routes) Register(api *gin.RouterGroup) {
	// ---- Health ----
	api.GET("/healthz", func(c *gin.Context) {
		c.String(200, "ok")
	})

	// ---- Swagger ----
	api.GET("/swagger/*any", func(c *gin.Context) {
		// If you're using swaggo docs package:
		// import "github.com/quantumauth-io/quantum-auth/docs"
		docs.SwaggerInfo.Host = c.Request.Host
		docs.SwaggerInfo.Schemes = []string{"https"}
		if c.Request.TLS == nil {
			docs.SwaggerInfo.Schemes = []string{"http"}
		}
		ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
	})

	// ---- Users ----
	api.POST("/users/register", r.h.RegisterUser)
	api.GET("/users/me", r.h.RetrieveUser)

	// ---- Devices ----
	api.POST("/devices/register", r.h.RegisterDevice)

	// ---- Auth ----
	api.POST("/auth/challenge", r.h.AuthChallenge)
	api.POST("/auth/verify", r.h.AuthVerify)
	api.POST("/auth/full-login", r.h.FullLogin)

	// ---- Newsletter ----
	api.POST("/newsletter/subscribe", r.h.NewsletterSubscribe)
	api.POST("/newsletter/unsubscribe", r.h.NewsletterUnsubscribe)

	// ---- Protected routes ----
	secured := api.Group("/api")
	secured.Use(qamw.QuantumAuthMiddleware(qamw.Config{
		Repo: r.repo,
	}))
	secured.GET("/secure-ping", r.h.SecurePing)
}
