package tests

import (
	"testing"

	"github.com/shutter-network/shutter-service-api/common"
	"github.com/stretchr/testify/suite"
)

type TestShutterService struct {
	suite.Suite

	testDB *common.TestDatabase

	// dbQuery *data.Queries
}

func TestMain(t *testing.T) {
	suite.Run(t, new(TestShutterService))
}

func (s *TestShutterService) TearDownAllSuite() {
	s.testDB.TearDown()
}

func (s *TestShutterService) SetupSuite() {
	// ctx := context.Background()
	// _, curFile, _, _ := runtime.Caller(0)
	// curDir := path.Dir(curFile)

	migrationsPath := "./migrations"
	s.testDB = common.SetupTestDatabase(migrationsPath)
}
