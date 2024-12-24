package service

import (
	"net/http"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/error"
	"github.com/shutter-network/shutter-service-api/internal/usecase"
)

type RegisterIdentityRequest struct {
	DecryptionTimestamp uint64 `json:"decryptionTimestamp"`
	IdentityPrefix      string `json:"identityPrefix"`
}

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

//	@BasePath	/api

// GetDecryptionKey godoc
//	@Summary		Get decryption key
//	@Description	Retrieves a decryption key for a given registered identity
//	@Tags			Crypto
//	@Produce		json
//	@Param			identity	query		string	true	"Identity associated with the decryption key"
//	@Success		200			{object}	usecase.GetDecryptionKeyResponse
//	@Failure		400			{object}	error.Http
//	@Failure		404			{object}	error.Http
//	@Failure		500			{object}	error.Http
//	@Router			/get_decryption_key [get]

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

//	@BasePath	/api

// GetDataForEncryption godoc
//	@Summary		Provides data necessary to allow encryption
//	@Description	This endpoint provides retrieval of all the necessary data required by users for encrypting any message
//	@Tags			Crypto
//	@Produce		json
//	@Param			address			query		string	true	"Ethereum address associated with the identity. If you are registering the identity yourself, pass the address of the account making the registration. If you want the API to register the identity, pass the address TBD."
//	@Param			identityPrefix	query		string	false	"Optional identity prefix. You can generate it on your end and pass it to this endpoint, or allow the API to randomly generate one for you."
//	@Success		200				{object}	usecase.GetDataForEncryptionResponse
//	@Failure		400				{object}	error.Http
//	@Failure		404				{object}	error.Http
//	@Failure		500				{object}	error.Http
//	@Router			/get_data_for_encryption [get]

func (svc *CryptoService) GetDataForEncryption(ctx *gin.Context) {
	address, ok := ctx.GetQuery("address")
	if !ok {
		err := error.NewHttpError(
			"query parameter not found",
			"address query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	identityPrefix, ok := ctx.GetQuery("identityPrefix")
	if !ok {
		identityPrefix = ""
	}

	data, httpErr := svc.CryptoUsecase.GetDataForEncryption(ctx, address, identityPrefix)
	if httpErr != nil {
		ctx.Error(httpErr)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}

//	@BasePath	/api

// RegisterIdentity godoc
//	@Summary		Allows users to register any identity
//	@Description	This endpoint allows user to register an identity which they used for encryption and set a particular timestamp for the release of the decryption key for the associated encrypted message.
//	@Tags			Crypto
//	@Produce		json
//	@Param			request	body		RegisterIdentityRequest	true	"Timestamp and Identity which user want to make the registration with"
//	@Success		200		{object}	usecase.RegisterIdentityResponse
//	@Failure		400		{object}	error.Http
//	@Failure		404		{object}	error.Http
//	@Failure		500		{object}	error.Http
//	@Router			/register_identity [post]

func (svc *CryptoService) RegisterIdentity(ctx *gin.Context) {
	var req RegisterIdentityRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Err(err).Msg("err decoding request body")
		err := error.NewHttpError(
			"unable to decode request body",
			"",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	data, httpErr := svc.CryptoUsecase.RegisterIdentity(ctx, req.DecryptionTimestamp, req.IdentityPrefix)
	if httpErr != nil {
		ctx.Error(httpErr)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}

func (svc *CryptoService) DecryptCommitment(ctx *gin.Context) {
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

	encryptedCommitment, ok := ctx.GetQuery("encryptedCommitment")
	if !ok {
		err := error.NewHttpError(
			"query parameter not found",
			"encrypted commitment query parameter is required",
			http.StatusBadRequest,
		)
		ctx.Error(err)
		return
	}

	data, err := svc.CryptoUsecase.DecryptCommitment(ctx, encryptedCommitment, identity)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message": data,
	})
}
