package tuf

import (
	"io"
	"os"
	"path/filepath"
)

type MockTufClient struct {
	srcPath string
	dstPath string
}

func NewMockTufClient(srcPath string, dstPath string) *MockTufClient {
	if srcPath == "" {
		panic("srcPath must be set")
	}
	if dstPath == "" {
		panic("dstPath must be set")
	}
	return &MockTufClient{
		srcPath: srcPath,
		dstPath: dstPath,
	}
}

func (dc *MockTufClient) DownloadTarget(target string, filePath string) (actualFilePath string, data []byte, err error) {
	src, err := os.Open(filepath.Join(dc.srcPath, target))
	if err != nil {
		return "", nil, err
	}
	defer src.Close()

	var dstFilePath string
	if filePath == "" {
		dstFilePath = filepath.Join(dc.dstPath, filepath.FromSlash(target))
	} else {
		dstFilePath = filePath
	}

	err = os.MkdirAll(filepath.Dir(dstFilePath), os.ModePerm)
	if err != nil {
		return "", nil, err
	}
	dst, err := os.Create(dstFilePath)
	if err != nil {
		return "", nil, err
	}
	defer dst.Close()

	// reading from tee will read from src and write to dst at the same time
	tee := io.TeeReader(src, dst)

	b, err := io.ReadAll(tee)
	if err != nil {
		return "", nil, err
	}

	return dstFilePath, b, nil
}

type MockVersionChecker struct {
	err error
}

func NewMockVersionChecker() *MockVersionChecker {
	return &MockVersionChecker{}
}

func (vc *MockVersionChecker) CheckVersion(_ Downloader) error {
	return vc.err
}
