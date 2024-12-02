package service

import (
	"net/http"
	"strconv"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/error"
	"github.com/shutter-network/shutter-service-api/internal/usecase"
)

type CryptoService struct {
	CryptoUsecase *usecase.CryptoUsecase
}

func NewCryptoService(
	db *pgxpool.Pool,
	contract *common.Contract,
	ethClient *ethclient.Client,
	config *common.Config,
) *CryptoService {
	return &CryptoService{
		CryptoUsecase: usecase.NewCryptoUsecase(db, contract.ShutterRegistryContract, contract.KeyperSetManagerContract, contract.KeyBroadcastContract, ethClient, config),
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

func (svc *CryptoService) GetDataForEncryption(ctx *gin.Context) {
	timestampStringified, ok := ctx.GetQuery("timestamp")
	if !ok {
		err := error.NewHttpError(
			"query parameter not found",
			"timestamp query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	timestamp, err := strconv.Atoi(timestampStringified)
	if err != nil {
		log.Err(err).Msg("err decoding timestamp")
		err := error.NewHttpError(
			"unable to decode timestamp",
			"valid timestamp query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	identityPrefix, ok := ctx.GetQuery("identityPrefix")
	if !ok {
		identityPrefix = ""
	}

	data, httpErr := svc.CryptoUsecase.GetDataForEncryption(ctx, uint64(timestamp), identityPrefix)
	if httpErr != nil {
		ctx.Error(httpErr)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}
