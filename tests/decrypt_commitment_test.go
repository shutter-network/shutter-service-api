package tests

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var msg = []byte("please hide this message")

type InsertDecryptCommitmentParams struct {
	blockNumber    int64
	blockHash      []byte
	txIndex        int64
	logIndex       int64
	eon            int64
	identityPrefix []byte
	sender         string
	timestamp      int64
	decrypted      bool
	identity       []byte
}

func (s *TestShutterService) TestDecryptionCommitmentNotFound() {
	ctx := context.Background()
	eon := rand.Int63()

	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)

	eonPublicKey, _, _ := s.makeKeys(identity)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)
	epochID := shcrypto.ComputeEpochID(identity)
	encryptedCommitment := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)

	encrypedCommitmentBytes := encryptedCommitment.Marshal()

	timestamp := 1732885990
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	blockHash, err := generateRandomBytes(32)
	s.Require().NoError(err)
	sender := "0xSomeaddress"

	err = InsertDecryptCommitment(ctx, s.testDB.DbInstance, &InsertDecryptCommitmentParams{
		blockNumber:    rand.Int63(),
		blockHash:      blockHash,
		txIndex:        rand.Int63(),
		logIndex:       rand.Int63(),
		eon:            eon,
		identityPrefix: identityPrefix,
		sender:         sender,
		timestamp:      int64(timestamp),
		decrypted:      false,
		identity:       epochID.Marshal(),
	})
	s.Require().NoError(err)
	identityStringified := hex.EncodeToString(identity)
	encryptedCommitmentStringified := hex.EncodeToString(encrypedCommitmentBytes)
	_, err = s.cryptoUsecase.DecryptCommitment(ctx, encryptedCommitmentStringified, identityStringified)
	s.Require().Error(err)
}

func (s *TestShutterService) TestDecryptionCommitment() {
	ctx := context.Background()
	eon := rand.Int63()

	identity, err := generateRandomBytes(32)
	s.Require().NoError(err)

	eonPublicKey, decryptionKey, epochID := s.makeKeys(identity)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)
	commitment := []byte(msg)
	encryptedCommitment := shcrypto.Encrypt(commitment, eonPublicKey, epochID, sigma)

	encrypedCommitmentBytes := encryptedCommitment.Marshal()

	timestamp := 1732885990
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	blockHash, err := generateRandomBytes(32)
	s.Require().NoError(err)
	sender := "0xSomeaddress"

	err = InsertDecryptCommitment(ctx, s.testDB.DbInstance, &InsertDecryptCommitmentParams{
		blockNumber:    rand.Int63(),
		blockHash:      blockHash,
		txIndex:        rand.Int63(),
		logIndex:       rand.Int63(),
		eon:            eon,
		identityPrefix: identityPrefix,
		sender:         sender,
		timestamp:      int64(timestamp),
		decrypted:      true,
		identity:       identity,
	})
	s.Require().NoError(err)

	err = InsertDecryptionKey(ctx, s.testDB.DbInstance, eon, identity, decryptionKey.Marshal())
	s.Require().NoError(err)

	identityStringified := hex.EncodeToString(identity)
	encryptedCommitmentStringified := hex.EncodeToString(encrypedCommitmentBytes)
	decryptedCommitment, err := s.cryptoUsecase.DecryptCommitment(ctx, encryptedCommitmentStringified, identityStringified)
	s.Require().Error(err)
	s.Require().Equal(decryptedCommitment, msg)
}

func InsertDecryptCommitment(ctx context.Context, db *pgxpool.Pool, params *InsertDecryptCommitmentParams) error {
	query := `INSERT INTO identity_registered_event (block_number, block_hash, tx_index, log_index, eon, identity_prefix, sender, timestamp, decrypted, identity) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := db.Exec(ctx, query, params.blockNumber, params.blockHash, params.txIndex, params.logIndex, params.eon, params.identityPrefix, params.sender, params.timestamp, params.decrypted, params.identity)
	if err != nil {
		return fmt.Errorf("failed to execute statement: %w", err)
	}

	return nil
}
