package tests

import (
	"context"
	cryptoRand "crypto/rand"
	"fmt"
	"math/rand"

	"github.com/jackc/pgx/v5/pgxpool"
)

func (s *TestShutterService) TestInsertDecryptionKey() {
	ctx := context.Background()
	eon := rand.Int63()
	epochID, err := generateRandomBytes(32)
	s.Require().NoError(err)
	decryptionKey, err := generateRandomBytes(32)
	s.Require().NoError(err)

	err = InsertDecryptionKey(ctx, s.testDB.DbInstance, eon, epochID, decryptionKey)
	s.Require().NoError(err)
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
