package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cryptorand "crypto/rand"

	"github.com/ethereum/go-ethereum/crypto"
	httpError "github.com/shutter-network/shutter-service-api/internal/error"
	"github.com/shutter-network/shutter-service-api/internal/service"
	"github.com/shutter-network/shutter-service-api/internal/usecase"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

var msg = []byte("please hide this message")

func (s *TestShutterService) TestRequestDecryptionKeyBeforeTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	query := fmt.Sprintf("?address=%s&identityPrefix=%s", address, identityPrefixStringified)
	url := "/api/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var dataForEncryptionResponse map[string]usecase.GetDataForEncryptionResponse
	err = json.Unmarshal(body, &dataForEncryptionResponse)
	s.Require().NoError(err)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	identityStringified := res.Identity

	decryptionTimestamp := time.Now().Add(1 * time.Hour).Unix()
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	url = "/api/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder = httptest.NewRecorder()

	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(http.StatusOK, recorder.Code)

	time.Sleep(30 * time.Second)

	query = fmt.Sprintf("?identity=%s", identityStringified)
	url = "/api/get_decryption_key" + query

	recorder = httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusBadRequest, recorder.Code)

	body, err = io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	s.Require().Equal(errorResponse.Description, "timestamp not reached yet, decryption key requested too early")
}

func (s *TestShutterService) TestRequestDecryptionKeyAfterTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	ctx := context.Background()
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	query := fmt.Sprintf("?address=%s&identityPrefix=%s", address, identityPrefixStringified)
	url := "/api/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var dataForEncryptionResponse map[string]usecase.GetDataForEncryptionResponse
	err = json.Unmarshal(body, &dataForEncryptionResponse)
	s.Require().NoError(err)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	identityBytes, err := hex.DecodeString(strings.TrimPrefix(res.Identity, "0x"))
	s.Require().NoError(err)

	eonKeyBytes, err := hex.DecodeString(strings.TrimPrefix(res.EonKey, "0x"))
	s.Require().NoError(err)

	epochID := shcrypto.ComputeEpochID(identityBytes)

	eonPublicKey := &shcrypto.EonPublicKey{}
	err = eonPublicKey.Unmarshal(eonKeyBytes)
	s.Require().NoError(err)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)

	encryptedMessage := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)

	block, err := s.ethClient.BlockByNumber(ctx, nil)
	s.Require().NoError(err)

	decryptionTimestamp := block.Header().Time + 10
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	url = "/api/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder = httptest.NewRecorder()

	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(http.StatusOK, recorder.Code)

	time.Sleep(30 * time.Second)

	query = fmt.Sprintf("?identity=%s", res.Identity)
	url = "/api/get_decryption_key" + query

	recorder = httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err = io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var decryptionKeyResponse map[string]usecase.GetDecryptionKeyResponse
	err = json.Unmarshal(body, &decryptionKeyResponse)
	s.Require().NoError(err)

	decryptionKeyStringified := decryptionKeyResponse["message"].DecryptionKey
	s.Require().NotEmpty(decryptionKeyStringified)

	decryptionKey := &shcrypto.EpochSecretKey{}
	decryptionKeyBytes, err := hex.DecodeString(strings.TrimPrefix(decryptionKeyStringified, "0x"))
	s.Require().NoError(err)
	err = decryptionKey.Unmarshal(decryptionKeyBytes)
	s.Require().NoError(err)

	decryptedMessage, err := encryptedMessage.Decrypt(decryptionKey)
	s.Require().NoError(err)
	s.Require().Equal(msg, decryptedMessage)
}

func (s *TestShutterService) TestRequestDecryptionKeyForUnregisteredIdentity() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	query := fmt.Sprintf("?address=%s&identityPrefix=%s", address, identityPrefixStringified)
	url := "/api/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var dataForEncryptionResponse map[string]usecase.GetDataForEncryptionResponse
	err = json.Unmarshal(body, &dataForEncryptionResponse)
	s.Require().NoError(err)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	query = fmt.Sprintf("?identity=%s", res.Identity)
	url = "/api/get_decryption_key" + query

	recorder = httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusBadRequest, recorder.Code)

	body, err = io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var errorResponse httpError.Http
	err = json.Unmarshal(body, &errorResponse)
	s.Require().NoError(err)

	s.Require().Equal(errorResponse.Description, "identity has not been registerd yet")
}

func (s *TestShutterService) TestRequestDecryptCommitmentAfterTimestampReached() {
	if testing.Short() {
		s.T().Skip("skipping integration test")
	}
	ctx := context.Background()
	address := crypto.PubkeyToAddress(*s.config.PublicKey).Hex()
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)

	query := fmt.Sprintf("?address=%s&identityPrefix=%s", address, identityPrefixStringified)
	url := "/api/get_data_for_encryption" + query

	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err := io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var dataForEncryptionResponse map[string]usecase.GetDataForEncryptionResponse
	err = json.Unmarshal(body, &dataForEncryptionResponse)
	s.Require().NoError(err)

	res := dataForEncryptionResponse["message"]
	s.Require().GreaterOrEqual(res.Eon, uint64(1))
	s.Require().NotNil(res.EonKey)
	s.Require().NotNil(res.Identity)
	s.Require().NotNil(res.IdentityPrefix)

	identityBytes, err := hex.DecodeString(strings.TrimPrefix(res.Identity, "0x"))
	s.Require().NoError(err)

	eonKeyBytes, err := hex.DecodeString(strings.TrimPrefix(res.EonKey, "0x"))
	s.Require().NoError(err)

	epochID := shcrypto.ComputeEpochID(identityBytes)

	eonPublicKey := &shcrypto.EonPublicKey{}
	eonPublicKey.Unmarshal(eonKeyBytes)

	sigma, err := shcrypto.RandomSigma(cryptorand.Reader)
	s.Require().NoError(err)

	encryptedCommitment := shcrypto.Encrypt(msg, eonPublicKey, epochID, sigma)
	encrypedCommitmentBytes := encryptedCommitment.Marshal()
	encryptedCommitmentStringified := hex.EncodeToString(encrypedCommitmentBytes)

	block, err := s.ethClient.BlockByNumber(ctx, nil)
	s.Require().NoError(err)
	decryptionTimestamp := block.Header().Time + 10
	reqBody := service.RegisterIdentityRequest{
		DecryptionTimestamp: uint64(decryptionTimestamp),
		IdentityPrefix:      identityPrefixStringified,
	}

	jsonData, err := json.Marshal(reqBody)
	s.Require().NoError(err)
	url = "/api/register_identity"

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	s.Require().NoError(err)

	req.Header.Set("Content-Type", "application/json")

	recorder = httptest.NewRecorder()

	s.router.ServeHTTP(recorder, req)
	s.Require().Equal(http.StatusOK, recorder.Code)

	time.Sleep(30 * time.Second)

	query = fmt.Sprintf("?identity=%s&encryptedCommitment=%s", res.Identity, encryptedCommitmentStringified)
	url = "/api/decrypt_commitment" + query

	recorder = httptest.NewRecorder()
	s.router.ServeHTTP(recorder, httptest.NewRequest("GET", url, nil))

	s.Require().Equal(http.StatusOK, recorder.Code)

	body, err = io.ReadAll(recorder.Body)
	s.Require().NoError(err)

	var decryptionKeyResponse map[string][]byte
	err = json.Unmarshal(body, &decryptionKeyResponse)
	s.Require().NoError(err)

	decryptedMessage := decryptionKeyResponse["message"]

	s.Require().NotEmpty(decryptedMessage)
	s.Require().Equal(msg, decryptedMessage)
}
