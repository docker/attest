package tuf

import (
	"io"
	"os"
	"path/filepath"
)

type mockTufClient struct {
	srcPath string
	dstPath string
}

func NewMockTufClient(srcPath string, dstPath string) *mockTufClient {
	if srcPath == "" {
		panic("srcPath must be set")
	}
	if dstPath == "" {
		panic("dstPath must be set")
	}
	return &mockTufClient{
		srcPath: srcPath,
		dstPath: dstPath,
	}
}

func (dc *mockTufClient) DownloadTarget(target string, filePath string) (actualFilePath string, data []byte, err error) {
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

	err = os.MkdirAll(filepath.Dir(dstFilePath), 0755)
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

type mockVersionChecker struct {
	err error
}

func NewMockVersionChecker() *mockVersionChecker {
	return &mockVersionChecker{}
}

func (vc *mockVersionChecker) CheckVersion(client TUFClient) error {
	return vc.err
}
