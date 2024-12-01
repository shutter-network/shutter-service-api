package usecase

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/data"
	httpError "github.com/shutter-network/shutter-service-api/internal/error"
)

type ShutterregistryInterface interface {
	Registrations(opts *bind.CallOpts, identity [32]byte) (
		struct {
			Eon       uint64
			Timestamp uint64
		},
		error,
	)
}

type GetDecryptionKeyResponse struct {
	DecryptionKey       string
	Identity            string
	DecryptionTimestamp uint64
}

type CryptoUsecase struct {
	db                      *pgxpool.Pool
	dbQuery                 *data.Queries
	shutterRegistryContract ShutterregistryInterface
	config                  *common.Config
}

func NewCryptoUsecase(
	db *pgxpool.Pool,
	shutterRegistryContract ShutterregistryInterface,
	config *common.Config,
) *CryptoUsecase {
	return &CryptoUsecase{
		db:                      db,
		dbQuery:                 data.New(db),
		shutterRegistryContract: shutterRegistryContract,
		config:                  config,
	}
}

func (uc *CryptoUsecase) GetDecryptionKey(ctx context.Context, identity string) (*GetDecryptionKeyResponse, *httpError.Http) {
	identityBytes, err := hex.DecodeString(strings.TrimPrefix(string(identity), "0x"))
	if err != nil {
		log.Err(err).Msg("err encountered while decoding identity")
		err := httpError.NewHttpError(
			"error encountered while decoding identity",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	if len(identityBytes) != 32 {
		log.Err(err).Msg("identity should be of length 32")
		err := httpError.NewHttpError(
			"identity should be of length 32",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	registrationData, err := uc.shutterRegistryContract.Registrations(nil, [32]byte(identityBytes))
	if err != nil {
		log.Err(err).Msg("err encountered while querying contract")
		err := httpError.NewHttpError(
			"error while querying for identity from the contract",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	if registrationData.Timestamp == 0 {
		log.Err(err).Msg("identity not registered")
		err := httpError.NewHttpError(
			"identity has not been registerd yet",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	currentTimestamp := time.Now().Unix()
	if currentTimestamp < int64(registrationData.Timestamp) {
		log.Err(err).Uint64("decryptionTimestamp", registrationData.Timestamp).Int64("currentTimestamp", currentTimestamp).Msg("timestamp not reached yet, decryption key requested too early")
		err := httpError.NewHttpError(
			"timestamp not reached yet, decryption key requested too early",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}

	var decryptionKey string

	decKey, err := uc.dbQuery.GetDecryptionKey(ctx, data.GetDecryptionKeyParams{
		Eon:     int64(registrationData.Eon),
		EpochID: identityBytes,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			// no data found try querying from other keyper via http
			decKey, err := uc.getDecryptionKeyFromExternalKeyper(ctx, int64(registrationData.Eon), identity)
			if err != nil {
				err := httpError.NewHttpError(
					err.Error(),
					"",
					http.StatusInternalServerError,
				)
				return nil, &err
			}
			if decKey == "" {
				err := httpError.NewHttpError(
					"decryption key doesnt exist",
					"",
					http.StatusNotFound,
				)
				return nil, &err
			}
			decryptionKey = decKey
		} else {
			log.Err(err).Msg("err encountered while querying db")
			err := httpError.NewHttpError(
				"error while querying db",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
	} else {
		decryptionKey = "0x" + hex.EncodeToString(decKey.DecryptionKey)
	}

	return &GetDecryptionKeyResponse{
		DecryptionKey:       decryptionKey,
		Identity:            identity,
		DecryptionTimestamp: registrationData.Timestamp,
	}, nil
}

func (uc *CryptoUsecase) getDecryptionKeyFromExternalKeyper(ctx context.Context, eon int64, identity string) (string, error) {
	path := uc.config.KeyperHTTPURL.JoinPath("/decryptionKey/", fmt.Sprint(eon), "/", identity)

	req, err := http.NewRequestWithContext(ctx, "GET", path.String(), http.NoBody)
	if err != nil {
		return "", err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get decryption key for eon %d and identity %s from keyper", eon, identity)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if res.StatusCode != http.StatusOK {
		return "", errors.Wrapf(err, "failed to get decryption key for eon %d and identity %s from keyper", eon, identity)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read keypers response body")
	}

	decryptionKey := string(body)

	return decryptionKey, nil
}
