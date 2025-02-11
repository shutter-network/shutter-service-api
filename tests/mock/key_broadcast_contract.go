package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/mock"
)

type MockKeyBroadcast struct {
	mock.Mock
}

func (m *MockKeyBroadcast) GetEonKey(opts *bind.CallOpts, eon uint64) ([]byte, error) {
	args := m.Called(nil, eon)
	return args.Get(0).([]byte), args.Error(1)
}
