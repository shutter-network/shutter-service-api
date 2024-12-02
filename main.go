package main

import (
	"context"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	shutterServiceCommon "github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/common/database"
	"github.com/shutter-network/shutter-service-api/internal/router"
)

func main() {
	port := os.Getenv("SERVER_PORT")

	ctx := context.Background()
	dbURL := database.GetDBURL()
	db, err := database.NewDB(ctx, dbURL)
	if err != nil {
		log.Info().Err(err).Msg("failed to initialize db")
		return
	}

	rpc_url := os.Getenv("RPC_URL")
	client, err := ethclient.Dial(rpc_url)
	if err != nil {
		log.Err(err).Msg("failed to initialize rpc client")
		return
	}

	shutterRegistryContractAddressStringified := os.Getenv("SHUTTER_REGISTRY_CONTRACT_ADDRESS")
	shutterRegistryContractAddress := common.HexToAddress(shutterRegistryContractAddressStringified)

	keyBroadcastContractAddressStringified := os.Getenv("KEY_BROADCAST_CONTRACT_ADDRESS")
	keyBroadcastContractAddress := common.HexToAddress(keyBroadcastContractAddressStringified)

	keyperSetManagerContractAddressStringified := os.Getenv("KEYPER_SET_MANAGER_CONTRACT_ADDRESS")
	keyperSetManagerContractAddress := common.HexToAddress(keyperSetManagerContractAddressStringified)

	contract, err := shutterServiceCommon.NewContract(client, shutterRegistryContractAddress, keyBroadcastContractAddress, keyperSetManagerContractAddress)
	if err != nil {
		log.Err(err).Msg("failed to instantiate shutter contracts")
		return
	}

	keyperHTTPUrl := os.Getenv("KEYPER_HTTP_URL")

	config, err := shutterServiceCommon.NewConfig(keyperHTTPUrl)
	if err != nil {
		log.Err(err).Msg("unable to parse keyper http url")
		return
	}
	app := router.NewRouter(db, contract, client, config)
	app.Run("0.0.0.0:" + port)
}
