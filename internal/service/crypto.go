package service

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
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
	eonStringified, ok := ctx.GetQuery("eon")
	if !ok {
		err := error.NewHttpError(
			"query parameter not found",
			"eon query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	eon, err := strconv.Atoi(eonStringified)
	if err != nil {
		log.Err(err).Msg("err decoding eon")
		err := error.NewHttpError(
			"unable to decode eon",
			"valid eon query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

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

	decryptionKey, httpErr := svc.CryptoUsecase.GetDecryptionKey(ctx, int64(eon), identity)
	if httpErr != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": decryptionKey,
	})
}
