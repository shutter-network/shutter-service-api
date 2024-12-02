package mock

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/mock"
)

type MockKeyperSetManager struct {
	mock.Mock
}

func (m *MockKeyperSetManager) GetKeyperSetIndexByBlock(opts *bind.CallOpts, blockNumber uint64) (uint64, error) {
	args := m.Called(opts, blockNumber)
	return args.Get(0).(uint64), args.Error(1)
}
