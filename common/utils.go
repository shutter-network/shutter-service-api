package common

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func ComputeIdentity(prefix []byte, sender common.Address) []byte {
	imageBytes := append(prefix, sender.Bytes()...)
	return crypto.Keccak256(imageBytes)
}

func PrefixWith0x(src string) string {
	return "0x" + src
}
