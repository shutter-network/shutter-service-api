package mock

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockEthClient struct {
	mock.Mock
}

func (m *MockEthClient) BlockNumber(ctx context.Context) (uint64, error) {
	args := m.Called(ctx)
	return args.Get(0).(uint64), args.Error(1)
}
