package main

import (
	"context"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-service-api/common/database"
	"github.com/shutter-network/shutter-service-api/internal/router"
)

func main() {
	port := os.Getenv("SERVER_PORT")

	ctx := context.Background()
	dbURL := database.GetDBURL()
	_, err := database.NewDB(ctx, dbURL)
	if err != nil {
		log.Info().Err(err).Msg("failed to initialize db")
		return
	}
	app := router.NewRouter()
	app.Run("0.0.0.0:" + port)
}
