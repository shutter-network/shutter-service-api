package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func NewRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	api := router.Group("/api")
	{
		hello := api.Group("/hello")
		hello.GET("", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "Hello",
			})
		})
	}
	return router
}