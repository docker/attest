package test

import (
	"context"
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/useragent"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	UseMockKMS                    = true
	AWSRegion                     = "us-east-1"
	AWSKMSKeyARN                  = "arn:aws:kms:us-east-1:175142243308:alias/doi-signing" // sandbox
	UnsignedLinuxAMD64ImageDigest = "sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620"
	UnsignedLinuxArm64ImageDigest = "sha256:7a76cec943853f9f7105b1976afa1bf7cd5bb6afc4e9d5852dd8da7cf81ae86e"
)

func UnsignedTestIndex(rel ...string) string {
	rel = append(rel, "test", "testdata", "unsigned-index")
	return filepath.Join(rel...)
}

func UnsignedTestImage(rel ...string) string {
	rel = append(rel, "test", "testdata", "unsigned-image")
	return filepath.Join(rel...)
}

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

//go:embed test-signing-key.pem
var signingKey []byte

func GetMockSigner(_ context.Context) (dsse.SignerVerifier, error) {
	return signerverifier.LoadKeyPair(signingKey)
}

func Setup(t *testing.T) (context.Context, dsse.SignerVerifier) {
	ctx := context.Background()
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

func NewLocalRegistry(ctx context.Context, options ...registry.Option) *httptest.Server {
	options = append(options, registry.Logger(log.New(io.Discard, "", log.LstdFlags)))
	regHandler := registry.New(options...)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the user agent
		ua := r.Header.Get("User-Agent")
		userAgent := useragent.Get(ctx)
		if !strings.HasPrefix(ua, userAgent) {
			http.Error(w, fmt.Sprintf("expected user agent to contain %q, got %q", userAgent, ua), http.StatusForbidden)
		}
		regHandler.ServeHTTP(w, r)
	}))
}

func PublicKeyToPEM(pubKey crypto.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
