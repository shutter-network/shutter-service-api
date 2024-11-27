package usecase

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
	contractBindings "github.com/shutter-network/contracts/v2/bindings/shutterregistry"
	"github.com/shutter-network/shutter-service-api/internal/error"
)

type CryptoUsecase struct {
	DB                      *pgxpool.Pool
	ShutterRegistryContract *contractBindings.Shutterregistry
}

func NewCryptoUsecase(
	db *pgxpool.Pool,
) *CryptoUsecase {
	return &CryptoUsecase{
		DB: db,
	}
}

func (uc *CryptoUsecase) GetDecryptionKey(ctx context.Context, eon int, identity string) *error.Http {
	identityBytes, err := hex.DecodeString(strings.TrimPrefix(string(identity), "0x"))
	if err != nil {
		log.Err(err).Msg("err encountered while decoding identity")
		err := error.NewHttpError(
			"error encountered while decoding identity",
			"",
			http.StatusInternalServerError,
		)
		return &err
	}

	decryptionTimestamp, err := uc.ShutterRegistryContract.Registrations(nil, [32]byte(identityBytes))
	if err != nil {
		log.Err(err).Msg("err encountered while querying contract")
		err := error.NewHttpError(
			"error while querying for identity from the contract",
			"",
			http.StatusInternalServerError,
		)
		return &err
	}

	currentTimestamp := time.Now().Unix()
	if currentTimestamp < int64(decryptionTimestamp) {
		log.Err(err).Uint64("decryptionTimestamp", decryptionTimestamp).Int64("currentTimestamp", currentTimestamp).Msg("timestamp not reached yet, decryption key requested too early")
		err := error.NewHttpError(
			"timestamp not reached yet, decryption key requested too early",
			"",
			http.StatusNotFound,
		)
		return &err
	}
	return nil
}
