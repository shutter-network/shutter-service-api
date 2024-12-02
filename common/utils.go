package common

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/shutter-network/rolling-shutter/rolling-shutter/medley/identitypreimage"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

func ComputeIdentity(prefix []byte, sender common.Address) *shcrypto.EpochID {
	imageBytes := append(prefix, sender.Bytes()...)
	return shcrypto.ComputeEpochID(identitypreimage.IdentityPreimage(imageBytes).Bytes())
}
