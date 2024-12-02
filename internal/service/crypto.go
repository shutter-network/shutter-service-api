package service

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shutter-network/contracts/v2/bindings/shutterregistry"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/error"
	"github.com/shutter-network/shutter-service-api/internal/usecase"
)

type CryptoService struct {
	CryptoUsecase *usecase.CryptoUsecase
}

func NewCryptoService(
	db *pgxpool.Pool,
	shutterRegistryContract *shutterregistry.Shutterregistry,
	config *common.Config,
) *CryptoService {
	return &CryptoService{
		CryptoUsecase: usecase.NewCryptoUsecase(db, shutterRegistryContract, config),
	}
}

func (svc *CryptoService) GetDecryptionKey(ctx *gin.Context) {
	identity, ok := ctx.GetQuery("identity")
	if !ok {
		err := error.NewHttpError(
			"query parameter not found",
			"identity query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	data, err := svc.CryptoUsecase.GetDecryptionKey(ctx, identity)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}
