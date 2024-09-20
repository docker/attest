//go:build e2e

package tlog

import (
	"context"
	"crypto/x509"
	_ "embed"
	"testing"
	"time"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: these are only run on CI to protect Rekor, but work just fine locally.
func TestRekor(t *testing.T) {
	// message digest
	payload := []byte("test")
	hash := util.SHA256(payload)
	// generate ephemeral keys to sign message digest
	signer, err := signerverifier.GenKeyPair()
	assert.NoError(t, err)
	sig, err := signer.Sign(context.Background(), hash)
	assert.NoError(t, err)
	opts := tuf.NewDockerDefaultClientOptions(t.TempDir())
	// use testing prefix in prod TUF
	opts.PathPrefix = "testing"

	real, err := tuf.NewClient(context.Background(), opts)
	require.NoError(t, err)

	tests := []struct {
		name          string
		tufDownloader tuf.Downloader
		pubKeysDir    string
	}{
		{name: "TestRekor (no tuf)"},
		{name: "TestRekor (with mock tuf)", tufDownloader: tuf.NewMockTufClient("."), pubKeysDir: "keys"},
		{name: "TestRekor (with real tuf)", tufDownloader: real},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := signer.Public()
			publicKey, err := x509.MarshalPKIXPublicKey(pk)
			if tt.tufDownloader != nil {
				// set to incorrect public key to test TUF flow
				keyStr, err := test.PublicKeyToPEM(pk)
				require.NoError(t, err)
				rekorPublicKey = []byte(keyStr)
			}
			if tt.pubKeysDir == "" {
				tt.pubKeysDir = defaultPublicKeysDir
			}
			rekor, err := NewRekorLog(WithTUFDownloader(tt.tufDownloader), WithTUFPublicKeysDir(tt.pubKeysDir))

			require.NoError(t, err)
			require.NotNil(t, rekor)
			ext, err := rekor.UploadEntry(context.Background(), "test", payload, sig, signer)
			require.NoError(t, err)
			require.NotNil(t, ext)
			assert.Equal(t, RekorTLExtKind, ext.Kind)
			assert.NotEmpty(t, ext.Data)

			when, err := rekor.VerifyEntry(context.Background(), ext, payload, publicKey)
			require.NoError(t, err)
			assert.WithinDuration(t, time.Now(), when, 5*time.Second)
		})
	}
}
