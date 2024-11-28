package router

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	shutterRegistryBindings "github.com/shutter-network/contracts/v2/bindings/shutterregistry"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/middleware"
	"github.com/shutter-network/shutter-service-api/internal/service"
)

func NewRouter(
	db *pgxpool.Pool,
	shutterRegistry *shutterRegistryBindings.Shutterregistry,
	config *common.Config,
) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.Use(middleware.ErrorHandler())

	cryptoService := service.NewCryptoService(db, shutterRegistry, config)
	api := router.Group("/api")
	{
		api.GET("/get_decryption_key", cryptoService.GetDecryptionKey)
	}
	return router
}
