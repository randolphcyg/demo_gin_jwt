package router

import (
	"github.com/gin-gonic/gin"

	"github.com/randolphcyg/demo_gin_jwt/controller"
	"github.com/randolphcyg/demo_gin_jwt/middleware"
)

func SetupRouter() *gin.Engine {
	engine := gin.New()

	engine.Use(gin.Logger())
	engine.Use(gin.Recovery())

	auth := engine.Group("/api/v1/")
	{
		auth.POST("/login", controller.Login)
	}

	// secure router write
	write := engine.Group("/api/v1/").Use(middleware.JWTAuth())
	{
		write.POST("/write", controller.Write)
	}

	// insecure router read
	read := engine.Group("/api/v1/")
	{
		read.POST("/read", controller.Read)
	}

	return engine
}
