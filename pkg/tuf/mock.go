package tuf

type MockVersionChecker struct {
	err error
}

func NewMockVersionChecker() *MockVersionChecker {
	return &MockVersionChecker{}
}

func (vc *MockVersionChecker) CheckVersion(_ Downloader) error {
	return vc.err
}
