package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/mock"
)

type MockShutterregistry struct {
	mock.Mock
}

func (m *MockShutterregistry) Registrations(opts *bind.CallOpts, identity [32]byte) (struct {
	Eon       uint64
	Timestamp uint64
}, error) {
	args := m.Called(opts, identity)
	return args.Get(0).(struct {
		Eon       uint64
		Timestamp uint64
	}), args.Error(1)
}

func (m *MockShutterregistry) Register(opts *bind.TransactOpts, eon uint64, identityPrefix [32]byte, timestamp uint64) (*types.Transaction, error) {
	args := m.Called(opts, eon, identityPrefix, timestamp)
	return args.Get(0).(*types.Transaction), args.Error(1)
}
