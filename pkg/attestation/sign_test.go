package attestation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/signerverifier"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyAttestation(t *testing.T) {
	ctx, signer := test.Setup(t)
	stmt := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: intoto.PredicateSPDX,
		},
		Predicate: "test",
	}

	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	opts := &attestation.SigningOptions{}
	env, err := attestation.SignDSSE(ctx, payload, signer, opts)
	require.NoError(t, err)

	// marshal envelope to json to test for bugs when marshaling envelope data
	serializedEnv, err := json.Marshal(env)
	require.NoError(t, err)
	deserializedEnv := new(attestation.Envelope)
	err = json.Unmarshal(serializedEnv, deserializedEnv)
	require.NoError(t, err)

	// signer.Public() calls AWS API when using AWS signer, use attestation.GetPublicVerificationKey() to get key from TUF repo
	// signer.Public() used here for test purposes
	ecPub, ok := signer.Public().(*ecdsa.PublicKey)
	assert.True(t, ok)
	pem, err := signerverifier.ConvertToPEM(ecPub)
	assert.NoError(t, err)
	keyID, err := signerverifier.KeyID(ecPub)
	assert.NoError(t, err)

	badKeyPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	badKey := &badKeyPriv.PublicKey
	badPEM, err := signerverifier.ConvertToPEM(badKey)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		keyID         string
		pem           []byte
		distrust      bool
		from          time.Time
		to            *time.Time
		status        string
		expectedError string
	}{
		{
			name:          "all OK",
			keyID:         keyID,
			pem:           pem,
			distrust:      false,
			from:          time.Time{},
			to:            nil,
			status:        "active",
			expectedError: "",
		},
		{
			name:          "key not found",
			keyID:         "someotherkey",
			pem:           pem,
			distrust:      false,
			from:          time.Time{},
			to:            nil,
			status:        "active",
			expectedError: fmt.Sprintf("key not found: %s", keyID),
		},
		{
			name:          "key distrusted",
			keyID:         keyID,
			pem:           pem,
			distrust:      true,
			from:          time.Time{},
			to:            nil,
			status:        "active",
			expectedError: "distrusted",
		},
		{
			name:          "key not yet valid",
			keyID:         keyID,
			pem:           pem,
			distrust:      false,
			from:          time.Now().Add(time.Hour),
			to:            nil,
			status:        "active",
			expectedError: "not yet valid",
		},
		{
			name:          "key already revoked",
			keyID:         keyID,
			pem:           pem,
			distrust:      false,
			from:          time.Time{},
			to:            new(time.Time),
			status:        "revoked",
			expectedError: "already revoked",
		},
		{
			name:          "bad key",
			keyID:         keyID,
			pem:           badPEM,
			distrust:      false,
			from:          time.Time{},
			to:            nil,
			status:        "active",
			expectedError: "signature is not valid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyMeta := &attestation.KeyMetadata{
				ID:       tc.keyID,
				PEM:      string(tc.pem),
				Distrust: tc.distrust,
				From:     tc.from,
				To:       tc.to,
				Status:   tc.status,
			}
			opts := &attestation.VerifyOptions{
				Keys: attestation.Keys{keyMeta},
			}
			_, err = attestation.VerifyDSSE(ctx, deserializedEnv, opts)
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
