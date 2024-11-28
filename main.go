package main

import (
	"context"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog/log"
	shutterRegistryBindings "github.com/shutter-network/contracts/v2/bindings/shutterregistry"
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

	shutterRegistryContractAddress := os.Getenv("REGISTRY_CONTRACT_ADDRESS")

	address := common.HexToAddress(shutterRegistryContractAddress)
	shutterRegistry, err := shutterRegistryBindings.NewShutterregistry(address, client)
	if err != nil {
		log.Err(err).Msg("failed to instantiate shutter registry contract")
		return
	}

	keyperHTTPUrl := os.Getenv("KEYPER_HTTP_URL")

	config, err := shutterServiceCommon.NewConfig(keyperHTTPUrl)
	if err != nil {
		log.Err(err).Msg("unable to parse keyper http url")
		return
	}
	app := router.NewRouter(db, shutterRegistry, config)
	app.Run("0.0.0.0:" + port)
}
