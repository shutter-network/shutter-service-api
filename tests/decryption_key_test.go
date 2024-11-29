package tests

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/mock"
)

func (s *TestShutterService) TestInsertDecryptionKey() {
	ctx := context.Background()
	eon := rand.Int63()
	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)
	decryptionKey, err := generateRandomBytes(32)
	s.Require().NoError(err)

	err = InsertDecryptionKey(ctx, s.testDB.DbInstance, eon, identity, decryptionKey)
	s.Require().NoError(err)
}

func (s *TestShutterService) TestGetDecryptionKey() {
	ctx := context.Background()
	eon := rand.Int63()
	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)
	decryptionKey, err := generateRandomBytes(32)
	s.Require().NoError(err)

	err = InsertDecryptionKey(ctx, s.testDB.DbInstance, eon, identity, decryptionKey)
	s.Require().NoError(err)

	s.shutterRegistryContract.
		On("Registrations", mock.AnythingOfType("*bind.CallOpts"), [32]byte(identity)).
		Return(uint64(1), nil).
		Once()

	identityStringified := hex.EncodeToString(identity)
	decKey, err := s.cryptoUsecase.GetDecryptionKey(ctx, eon, identityStringified)
	s.Require().Nil(err)

	s.Require().Equal(decKey, "0x"+hex.EncodeToString(decryptionKey))
}

func (s *TestShutterService) TestGetDecryptionKeyNotRegistered() {
	ctx := context.Background()
	eon := rand.Int63()
	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)
	decryptionKey, err := generateRandomBytes(32)
	s.Require().NoError(err)

	err = InsertDecryptionKey(ctx, s.testDB.DbInstance, eon, identity, decryptionKey)
	s.Require().NoError(err)

	s.shutterRegistryContract.
		On("Registrations", mock.AnythingOfType("*bind.CallOpts"), [32]byte(identity)).
		Return(uint64(0), nil).
		Once()

	identityStringified := hex.EncodeToString(identity)
	_, err = s.cryptoUsecase.GetDecryptionKey(ctx, eon, identityStringified)
	s.Require().Error(err)
}

func InsertDecryptionKey(ctx context.Context, db *pgxpool.Pool, eon int64, epochID, decryptionKey []byte) error {
	query := `INSERT INTO decryption_key (eon, epoch_id, decryption_key) VALUES ($1, $2, $3)`

	_, err := db.Exec(ctx, query, eon, epochID, decryptionKey)
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := cryptoRand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
