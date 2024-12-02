package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/mock"
)

type MockKeyperBroadcast struct {
	mock.Mock
}

func (m *MockKeyperBroadcast) GetEonKey(opts *bind.CallOpts, eon uint64) ([]byte, error) {
	args := m.Called(opts, eon)
	return args.Get(0).([]byte), args.Error(1)
}
