package tests

import (
	"context"
	"encoding/hex"
	"math/rand"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/shutter-network/shutter-service-api/common"
)

func (s *TestShutterService) TestRegisterIdentity() {
	ctx := context.Background()
	decryptionTimestamp := 1732885990
	identityPrefix, err := generateRandomBytes(32)
	s.Require().NoError(err)
	identityPrefixStringified := hex.EncodeToString(identityPrefix)
	blockNumber := rand.Uint64()

	eon := rand.Uint64()

	eonPublicKey, _, _ := s.makeKeys()

	s.ethClient.
		On("BlockNumber", ctx).
		Return(blockNumber, nil).
		Once()

	s.keyperSetManagerContract.
		On("GetKeyperSetIndexByBlock", nil, blockNumber).
		Return(eon, nil).
		Once()

	s.keyBroadcastContract.
		On("GetEonKey", nil, eon).
		Return(eonPublicKey.Marshal(), nil).
		Once()

	data, err := s.cryptoUsecase.RegisterIdentity(ctx, uint64(decryptionTimestamp), identityPrefixStringified)
	s.Require().Nil(err)

	identity := common.ComputeIdentity(identityPrefix, ethCommon.HexToAddress(sender))

	s.Require().Equal(data.Eon, eon)
	s.Require().Equal(hex.EncodeToString(identity.Marshal()), data.Identity)
	s.Require().Equal(hex.EncodeToString(identityPrefix), data.IdentityPrefix)
	s.Require().Equal(data.EonKey, hex.EncodeToString(eonPublicKey.Marshal()))
}
