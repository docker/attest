package test

import (
	"context"
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/useragent"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tlog"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	UseMockTL  = true
	UseMockKMS = true

	AWSRegion    = "us-east-1"
	AWSKMSKeyARN = "arn:aws:kms:us-east-1:175142243308:alias/doi-signing" // sandbox
)

func UnsignedTestImage(rel ...string) string {
	rel = append(rel, "test", "testdata", "unsigned-test-image")
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

func NewLocalRegistry(ctx context.Context, options ...registry.Option) *httptest.Server {
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

func publicKeyToPEM(pubKey crypto.PublicKey) (string, error) {
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

// LoadKeyMetadata loads the key metadata for the given signer verifier.
func GenKeyMetadata(sv dsse.SignerVerifier) (*attestation.KeyMetadata, error) {
	pub := sv.Public()
	pem, err := publicKeyToPEM(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}
	id, err := sv.KeyID()
	if err != nil {
		return nil, err
	}

	return &attestation.KeyMetadata{
		ID:            id,
		Status:        "active",
		SigningFormat: "dssev1",
		From:          time.Now(),
		PEM:           pem,
	}, nil
}
