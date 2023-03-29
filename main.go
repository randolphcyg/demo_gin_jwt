package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/randolphcyg/demo_gin_jwt/router"
)

func main() {
	engine := router.SetupRouter()

	engine.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Gin Server")
	})

	err := engine.Run(":8090")
	if err != nil {
		panic(err)
	}
}
