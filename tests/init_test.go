package tests

import (
	"net/url"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/shutter-network/shutter-service-api/common"
	"github.com/shutter-network/shutter-service-api/internal/data"
	"github.com/shutter-network/shutter-service-api/internal/usecase"
	"github.com/shutter-network/shutter-service-api/tests/mock"
	"github.com/stretchr/testify/suite"
)

type TestShutterService struct {
	suite.Suite
	testDB                  *common.TestDatabase
	dbQuery                 *data.Queries
	cryptoUsecase           *usecase.CryptoUsecase
	config                  *common.Config
	shutterRegistryContract *mock.MockShutterregistry
}

func TestShutterServiceSuite(t *testing.T) {
	suite.Run(t, new(TestShutterService))
}

func (s *TestShutterService) TearDownAllSuite() {
	s.testDB.TearDown()
}

func (s *TestShutterService) SetupSuite() {
	migrationsPath := "./migrations"
	s.testDB = common.SetupTestDatabase(migrationsPath)
	s.dbQuery = data.New(s.testDB.DbInstance)
	parsedURL, err := url.Parse("https://keyperurl.com")
	if err != nil {
		log.Err(err).Msg("error while parsing url")
		return
	}
	s.config = &common.Config{
		KeyperHTTPURL: parsedURL,
	}
	s.shutterRegistryContract = new(mock.MockShutterregistry)

	s.cryptoUsecase = usecase.NewCryptoUsecase(s.testDB.DbInstance, s.shutterRegistryContract, s.config)
}
