package common

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shutter-network/contracts/v2/bindings/keybroadcastcontract"
	"github.com/shutter-network/contracts/v2/bindings/keypersetmanager"
	"github.com/shutter-network/contracts/v2/bindings/shutterregistry"
)

type Contract struct {
	ShutterRegistryContract  *shutterregistry.Shutterregistry
	KeyperSetManagerContract *keypersetmanager.Keypersetmanager
	KeyBroadcastContract     *keybroadcastcontract.Keybroadcastcontract
}

func NewContract(
	ethClient *ethclient.Client,
	shutterRegistryContractAddress common.Address,
	keyperSetManagerContractAddress common.Address,
	keyBroadcastContractAddress common.Address,
) (*Contract, error) {
	shutterRegistryContract, err := shutterregistry.NewShutterregistry(shutterRegistryContractAddress, ethClient)
	if err != nil {
		return nil, err
	}

	keyperSetManagerContract, err := keypersetmanager.NewKeypersetmanager(keyperSetManagerContractAddress, ethClient)
	if err != nil {
		return nil, err
	}

	keyBroadcastContract, err := keybroadcastcontract.NewKeybroadcastcontract(keyBroadcastContractAddress, ethClient)
	if err != nil {
		return nil, err
	}
	return &Contract{
		ShutterRegistryContract:  shutterRegistryContract,
		KeyperSetManagerContract: keyperSetManagerContract,
		KeyBroadcastContract:     keyBroadcastContract,
	}, nil
}
