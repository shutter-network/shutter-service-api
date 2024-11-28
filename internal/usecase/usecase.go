package usecase

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shutter-network/contracts/v2/bindings/shutterregistry"
	"github.com/shutter-network/shutter-service-api/common"
)

// regsiters usecases in this file
type Usecase struct {
	CryptoUsecase *CryptoUsecase
}

func NewUsecase(
	db *pgxpool.Pool,
	shutterRegistryContract *shutterregistry.Shutterregistry,
	config *common.Config,
) *Usecase {
	return &Usecase{
		CryptoUsecase: NewCryptoUsecase(db, shutterRegistryContract, config),
	}
}
