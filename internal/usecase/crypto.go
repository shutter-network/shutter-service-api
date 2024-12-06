package usecase

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	cryptorand "crypto/rand"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/data"
	httpError "github.com/shutter-network/shutter-service-api/internal/error"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

const IdentityPrefixByteLength = 32

type ShutterregistryInterface interface {
	Registrations(opts *bind.CallOpts, identity [32]byte) (
		struct {
			Eon       uint64
			Timestamp uint64
		},
		error,
	)
	Register(opts *bind.TransactOpts, eon uint64, identityPrefix [32]byte, timestamp uint64) (*types.Transaction, error)
}

type KeyperSetManagerInterface interface {
	GetKeyperSetIndexByBlock(opts *bind.CallOpts, blockNumber uint64) (uint64, error)
}

type KeyBroadcastInterface interface {
	GetEonKey(opts *bind.CallOpts, eon uint64) ([]byte, error)
}

type EthClientInterface interface {
	BlockNumber(ctx context.Context) (uint64, error)
	ChainID(ctx context.Context) (*big.Int, error)
}

type GetDecryptionKeyResponse struct {
	DecryptionKey       string
	Identity            string
	DecryptionTimestamp uint64
}

type GetDataForEncryptionResponse struct {
	Eon            uint64
	Identity       string
	IdentityPrefix string
	EonKey         string
}

type RegisterIdentityResponse struct {
	Eon            uint64
	Identity       string
	IdentityPrefix string
	EonKey         string
	TxHash         string
}

type CryptoUsecase struct {
	db                       *pgxpool.Pool
	dbQuery                  *data.Queries
	shutterRegistryContract  ShutterregistryInterface
	keyperSetManagerContract KeyperSetManagerInterface
	keyBroadcastContract     KeyBroadcastInterface
	ethClient                EthClientInterface
	config                   *common.Config
}

func NewCryptoUsecase(
	db *pgxpool.Pool,
	shutterRegistryContract ShutterregistryInterface,
	keyperSetManagerContract KeyperSetManagerInterface,
	keyBroadcastContract KeyBroadcastInterface,
	ethClient EthClientInterface,
	config *common.Config,
) *CryptoUsecase {
	return &CryptoUsecase{
		db:                       db,
		dbQuery:                  data.New(db),
		shutterRegistryContract:  shutterRegistryContract,
		keyperSetManagerContract: keyperSetManagerContract,
		keyBroadcastContract:     keyBroadcastContract,
		ethClient:                ethClient,
		config:                   config,
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
		log.Debug().Uint64("decryptionTimestamp", registrationData.Timestamp).Int64("currentTimestamp", currentTimestamp).Msg("timestamp not reached yet, decryption key requested too early")
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

func (uc *CryptoUsecase) GetDataForEncryption(ctx context.Context, address string, identityPrefixStringified string) (*GetDataForEncryptionResponse, *httpError.Http) {
	if !ethCommon.IsHexAddress(address) {
		log.Warn().Str("address", address).Msg("invalid address")
		err := httpError.NewHttpError(
			"invalid address",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}
	var identityPrefix shcrypto.Block

	if len(identityPrefixStringified) > 0 {
		trimmedIdentityPrefix := strings.TrimPrefix(identityPrefixStringified, "0x")
		if len(trimmedIdentityPrefix) != 2*IdentityPrefixByteLength {
			log.Warn().Msg("identity prefix should be of byte length 32")
			err := httpError.NewHttpError(
				"identity prefix should be of length 32",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefixBytes, err := hex.DecodeString(trimmedIdentityPrefix)
		if err != nil {
			log.Err(err).Msg("err encountered while decoding identity prefix")
			err := httpError.NewHttpError(
				"error encountered while decoding identity prefix",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefix = shcrypto.Block(identityPrefixBytes)
	} else {
		// generate a random one
		block, err := shcrypto.RandomSigma(cryptorand.Reader)
		if err != nil {
			log.Err(err).Msg("err encountered while generating identity prefix")
			err := httpError.NewHttpError(
				"error encountered while generating identity prefix",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
		identityPrefix = block
	}

	blockNumber, err := uc.ethClient.BlockNumber(ctx)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for recent block")
		err := httpError.NewHttpError(
			"error encountered while querying for recent block",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eon, err := uc.keyperSetManagerContract.GetKeyperSetIndexByBlock(nil, blockNumber)
	if err != nil {
		log.Err(err).Msg("err encountered while querying keyper set index")
		err := httpError.NewHttpError(
			"error encountered while querying for keyper set index",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKeyBytes, err := uc.keyBroadcastContract.GetEonKey(nil, eon)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for eon key")
		err := httpError.NewHttpError(
			"error encountered while querying for eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKey := &shcrypto.EonPublicKey{}
	if err := eonKey.Unmarshal(eonKeyBytes); err != nil {
		log.Err(err).Msg("err encountered while deserializing eon key")
		err := httpError.NewHttpError(
			"error encountered while querying deserializing eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	identity := common.ComputeIdentity(identityPrefix[:], ethCommon.HexToAddress(address))

	return &GetDataForEncryptionResponse{
		Eon:            eon,
		Identity:       hex.EncodeToString(identity),
		IdentityPrefix: hex.EncodeToString(identityPrefix[:]),
		EonKey:         hex.EncodeToString(eonKeyBytes),
	}, nil
}

func (uc *CryptoUsecase) RegisterIdentity(ctx context.Context, decryptionTimestamp uint64, identityPrefixStringified string) (*RegisterIdentityResponse, *httpError.Http) {
	currentTimestamp := time.Now().Unix()
	if currentTimestamp > int64(decryptionTimestamp) {
		log.Debug().Uint64("decryptionTimestamp", decryptionTimestamp).Int64("currentTimestamp", currentTimestamp).Msg("decryption timestamp should be in future")
		err := httpError.NewHttpError(
			"decryption timestamp should be in future",
			"",
			http.StatusBadRequest,
		)
		return nil, &err
	}
	var identityPrefix shcrypto.Block

	if len(identityPrefixStringified) > 0 {
		trimmedIdentityPrefix := strings.TrimPrefix(identityPrefixStringified, "0x")
		if len(trimmedIdentityPrefix) != 2*IdentityPrefixByteLength {
			log.Warn().Msg("identity prefix should be of byte length 32")
			err := httpError.NewHttpError(
				"identity prefix should be of byte length 32",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefixBytes, err := hex.DecodeString(trimmedIdentityPrefix)
		if err != nil {
			log.Err(err).Msg("err encountered while decoding identity prefix")
			err := httpError.NewHttpError(
				"error encountered while decoding identity prefix",
				"",
				http.StatusBadRequest,
			)
			return nil, &err
		}
		identityPrefix = shcrypto.Block(identityPrefixBytes)
	} else {
		// generate a random one
		block, err := shcrypto.RandomSigma(cryptorand.Reader)
		if err != nil {
			log.Err(err).Msg("err encountered while generating identity prefix")
			err := httpError.NewHttpError(
				"error encountered while generating identity prefix",
				"",
				http.StatusInternalServerError,
			)
			return nil, &err
		}
		identityPrefix = block
	}

	blockNumber, err := uc.ethClient.BlockNumber(ctx)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for recent block")
		err := httpError.NewHttpError(
			"error encountered while querying for recent block",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eon, err := uc.keyperSetManagerContract.GetKeyperSetIndexByBlock(nil, blockNumber)
	if err != nil {
		log.Err(err).Msg("err encountered while querying keyper set index")
		err := httpError.NewHttpError(
			"error encountered while querying for keyper set index",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKeyBytes, err := uc.keyBroadcastContract.GetEonKey(nil, eon)
	if err != nil {
		log.Err(err).Msg("err encountered while querying for eon key")
		err := httpError.NewHttpError(
			"error encountered while querying for eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	eonKey := &shcrypto.EonPublicKey{}
	if err := eonKey.Unmarshal(eonKeyBytes); err != nil {
		log.Err(err).Msg("err encountered while deserializing eon key")
		err := httpError.NewHttpError(
			"error encountered while querying deserializing eon key",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	chainId, err := uc.ethClient.ChainID(ctx)
	if err != nil {
		log.Err(err).Msg("err encountered while quering chain id")
		err := httpError.NewHttpError(
			"error encountered while querying chain id",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	newSigner, err := bind.NewKeyedTransactorWithChainID(uc.config.SigningKey, chainId)
	if err != nil {
		log.Err(err).Msg("err encountered while creating signer")
		err := httpError.NewHttpError(
			"error encountered while registering identity",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}

	identity := common.ComputeIdentity(identityPrefix[:], newSigner.From)

	publicAddress := crypto.PubkeyToAddress(*uc.config.PublicKey)

	opts := bind.TransactOpts{
		From:   publicAddress,
		Signer: newSigner.Signer,
	}

	tx, err := uc.shutterRegistryContract.Register(&opts, eon, identityPrefix, decryptionTimestamp)
	if err != nil {
		log.Err(err).Msg("failed to send transaction")
		err := httpError.NewHttpError(
			"failed to register identity",
			"",
			http.StatusInternalServerError,
		)
		return nil, &err
	}
	// not launching a routine to monitor the transaction
	// we return the transaction hash in response to allow
	// users the ability to monitor it themselves

	return &RegisterIdentityResponse{
		Eon:            eon,
		Identity:       hex.EncodeToString(identity),
		IdentityPrefix: hex.EncodeToString(identityPrefix[:]),
		EonKey:         hex.EncodeToString(eonKeyBytes),
		TxHash:         tx.Hash().Hex(),
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
