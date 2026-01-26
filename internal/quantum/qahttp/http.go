package qahttp

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	qagin "github.com/quantumauth-io/go-quantumauth-mw/gin"
	"github.com/quantumauth-io/quantum-auth/docs"
	_ "github.com/quantumauth-io/quantum-auth/docs"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/authmw"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/email"
	"github.com/quantumauth-io/quantum-go-utils/qa/headers"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type Routes struct {
	h    *Handler
	sh   *SecureHandlers
	repo *database.QuantumAuthRepository
}

// NewRoutes builds your main API route registrar
func NewRoutes(ctx context.Context, repo *database.QuantumAuthRepository, emailSender *email.SMTPSender) *Routes {
	return &Routes{
		h:    NewHandler(ctx, repo, emailSender),
		sh:   NewSecureHandler(ctx, repo, emailSender),
		repo: repo,
	}
}

// NewRouter creates the Gin engine + registers ALL routes
func NewRouter(ctx context.Context, repo *database.QuantumAuthRepository, emailSender *email.SMTPSender) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	_ = r.SetTrustedProxies(nil)

	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:4321",
			"http://127.0.0.1:4321",
			"https://dev.quantumauth.io",
			"https://quantumauth.io",
		},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			string(headers.HeaderAuthorization),

			string(headers.HeaderQAAppID),
			string(headers.HeaderQAAudience),
			string(headers.HeaderQATimestamp),
			string(headers.HeaderQAChallengeID),
			string(headers.HeaderQAUserID),
			string(headers.HeaderQADeviceID),
			string(headers.HeaderQABodySHA256),
			string(headers.HeaderQAVersion),
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	api := r.Group(constants.ApiBase)

	mainRoutes := NewRoutes(ctx, repo, emailSender)
	mainRoutes.Register(api)

	return r
}

func (r *Routes) Register(api *gin.RouterGroup) {

	api.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	if swaggerEnabled() {
		api.GET("/swagger/*any", func(c *gin.Context) {
			docs.SwaggerInfo.Host = c.Request.Host

			if c.Request.TLS != nil {
				docs.SwaggerInfo.Schemes = []string{"https"}
			} else {
				docs.SwaggerInfo.Schemes = []string{"http"}
			}

			ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
		})
	}

	// ---- Users ----
	api.POST("/users/register", r.h.RegisterUser)
	api.POST("/users/me", r.h.RetrieveUser)

	// ---- Devices ----
	api.POST("/devices/register", r.h.RegisterDevice)

	// ---- Auth ----
	api.POST("/auth/challenge", r.h.AuthChallenge)
	api.POST("/auth/verify", r.h.AuthVerify)
	api.POST("/auth/full-login", r.h.FullLogin)

	// ---- Newsletter ----
	api.POST("/newsletter/subscribe", r.h.NewsletterSubscribe)
	api.POST("/newsletter/unsubscribe", r.h.NewsletterUnsubscribe)

	// ---- QA Protected routes
	qaSecured := api.Group("/secured")
	v := &authmw.LocalVerifier{Repo: r.repo}
	qaSecured.Use(qagin.Middleware(v))

	qaSecured.GET("/qa/users/me", r.sh.RetrieveUserProfile)
	qaSecured.PATCH("/qa/users/me", r.sh.UpdateUserProfile)

	qaSecured.GET("/qa/devices", r.sh.ListMyDevices)
	qaSecured.PATCH("/qa/devices/:device_id", r.sh.UpdateMyDevice)

	qaSecured.POST("/qa/apps", r.sh.CreateApp)
	qaSecured.GET("/qa/apps", r.sh.ListMyApps)
	qaSecured.GET("/qa/apps/:app_id", r.sh.GetMyApp)
	qaSecured.PATCH("/qa/apps/:app_id", r.sh.UpdateMyApp)

}
