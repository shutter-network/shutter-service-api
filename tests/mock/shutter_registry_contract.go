package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/mock"
)

type MockShutterregistry struct {
	mock.Mock
}

func (m *MockShutterregistry) Registrations(opts *bind.CallOpts, identity [32]byte) (uint64, error) {
	args := m.Called(opts, identity)
	return args.Get(0).(uint64), args.Error(1)
}
