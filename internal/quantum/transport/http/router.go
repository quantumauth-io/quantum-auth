package transport

import "github.com/gin-gonic/gin"

type RouteRegistrar interface {
	Register(r *gin.RouterGroup)
}

func BuildEngine(registrars ...RouteRegistrar) *gin.Engine {
	r := gin.Default()
	err := r.SetTrustedProxies(nil)
	if err != nil {
		return nil
	}

	api := r.Group("")
	for _, rr := range registrars {
		rr.Register(api)
	}
	return r
}
