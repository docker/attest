package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/attest/pkg/signerverifier"
	"github.com/docker/attest/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	UseMockTL     = true
	UseMockKMS    = true
	UseMockPolicy = true

	AWSRegion    = "us-east-1"
	AWSKMSKeyARN = "arn:aws:kms:us-east-1:175142243308:alias/doi-signing" // sandbox
)

var UnsignedTestImage = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")

func CreateTempDir(t *testing.T, dir, pattern string) string {
	// Create a temporary directory for output oci layout
	tempDir, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Register a cleanup function to delete the temp directory when the test exits
	t.Cleanup(func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temp directory: %v", err)
		}
	})
	return tempDir
}

func GetMockSigner(_ context.Context) (dsse.SignerVerifier, error) {
	priv, err := os.ReadFile(filepath.Join("..", "..", "test", "testdata", "test-signing-key.pem"))
	if err != nil {
		return nil, err
	}
	return signerverifier.LoadKeyPair(priv)
}

func Setup(t *testing.T) (context.Context, dsse.SignerVerifier) {
	var tl tlog.TL
	if UseMockTL {
		tl = tlog.GetMockTL()
	} else {
		tl = &tlog.RekorTL{}
	}

	ctx := tlog.WithTL(context.Background(), tl)

	var signer dsse.SignerVerifier
	var err error
	if UseMockKMS {
		signer, err = GetMockSigner(ctx)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		signer, err = signerverifier.GetAWSSigner(ctx, AWSKMSKeyARN, AWSRegion)
		if err != nil {
			t.Fatal(err)
		}
	}

	return ctx, signer
}
