package attestation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/oci"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tlog"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockFactory struct{}

func (m *MockFactory) NewVerifier(_ context.Context, sig *attestation.Signature, opts *attestation.VerifyOptions) (dsse.Verifier, error) {
	ecdsaVerifier, err := attestation.NewECDSAVerifier(sig, opts)
	if err != nil {
		return nil, err
	}
	tlVerifier, err := attestation.NewTransparencyLogVerifier(sig, tlog.GetMockTL(), opts)
	if err != nil {
		return nil, err
	}
	return signerverifier.NewCompositeVerifier(ecdsaVerifier, tlVerifier), nil
}

func NewMockedTransparencyVerifierFactory() attestation.VerifierFactory {
	return &MockFactory{}
}

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
	tl := tlog.GetMockTL()
	opts := &attestation.SigningOptions{
		TransparencyLogger: tl,
	}
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
			factory := NewMockedTransparencyVerifierFactory()
			_, err = attestation.VerifyDSSE(ctx, factory, deserializedEnv, opts)
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAddSignedLayerAnnotations(t *testing.T) {
	ctx, signer := test.Setup(t)
	testCases := []struct {
		name    string
		replace bool
	}{
		{"replaced", true},
		{"not replaced", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("signed")
			testLayer := static.NewLayer(data, types.MediaType(intoto.PayloadType))
			mediaType := types.OCIManifestSchema1
			opts := &attestation.SigningOptions{}
			originalLayer := &attestation.Layer{
				Layer: testLayer,
				Statement: &intoto.Statement{
					StatementHeader: intoto.StatementHeader{
						PredicateType: attestation.VSAPredicateType,
					},
				},
				Annotations: map[string]string{"test": "test"},
			}

			manifest := &attestation.Manifest{
				OriginalDescriptor: &v1.Descriptor{
					MediaType: mediaType,
				},
				OriginalLayers: []*attestation.Layer{
					originalLayer,
				},
				SubjectDescriptor: &v1.Descriptor{},
			}
			err := manifest.Add(ctx, signer, originalLayer.Statement, opts)
			require.NoError(t, err)

			newImg, err := manifest.BuildImage(attestation.WithReplacedLayers(tc.replace))
			require.NoError(t, err)
			mf, _ := newImg.RawManifest()
			type Annotations struct {
				Annotations map[string]string `json:"annotations"`
			}
			type Layers struct {
				Layers []Annotations `json:"layers"`
			}
			l := &Layers{}
			err = json.Unmarshal(mf, l)
			require.NoError(t, err)
			_, ok := l.Layers[0].Annotations["test"]
			assert.Truef(t, ok, "missing annotations")
		})
	}
}

func TestSimpleStatementSigning(t *testing.T) {
	ctx, signer := test.Setup(t)
	empty := types.MediaType("application/vnd.oci.empty.v1+json")
	testCases := []struct {
		name    string
		replace bool
	}{
		{"replaced", true},
		{"not replaced", false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &attestation.SigningOptions{}
			statement := &intoto.Statement{
				StatementHeader: intoto.StatementHeader{
					PredicateType: attestation.VSAPredicateType,
				},
			}
			statement2 := &intoto.Statement{
				StatementHeader: intoto.StatementHeader{
					PredicateType: attestation.VSAPredicateType,
				},
			}
			digest, err := v1.NewHash("sha256:da8b190665956ea07890a0273e2a9c96bfe291662f08e2860e868eef69c34620")
			require.NoError(t, err)
			subject := &v1.Descriptor{
				MediaType: "application/vnd.oci.image.manifest.v1+json",
				Digest:    digest,
			}
			manifest, err := attestation.NewManifest(subject)
			require.NoError(t, err)
			err = manifest.Add(ctx, signer, statement, opts)
			require.NoError(t, err)

			err = manifest.Add(ctx, signer, statement2, opts)
			require.NoError(t, err)

			// fake that the manfifest was loaded from a real image
			manifest.OriginalLayers = manifest.SignedLayers
			envelopes, err := attestation.ExtractEnvelopes(manifest, attestation.VSAPredicateType)
			require.NoError(t, err)
			assert.Len(t, envelopes, 2)

			newImg, err := manifest.BuildImage(attestation.WithReplacedLayers(tc.replace))
			require.NoError(t, err)
			layers, err := newImg.Layers()
			require.NoError(t, err)
			if tc.replace {
				assert.Len(t, layers, 2)
			} else {
				assert.Len(t, layers, 4)
			}

			newImgs, err := manifest.BuildReferringArtifacts()
			require.NoError(t, err)
			assert.Len(t, newImgs, 2)
			for _, img := range newImgs {
				mf, err := img.Manifest()
				require.NoError(t, err)
				assert.Contains(t, mf.ArtifactType, "application/vnd.in-toto")
				assert.Contains(t, mf.ArtifactType, "+dsse")
				assert.Equal(t, subject.MediaType, mf.MediaType)
				assert.Equal(t, empty, mf.Config.MediaType)
				assert.Equal(t, int64(2), mf.Config.Size)
				assert.Equal(t, "{}", string(mf.Config.Data))
				layers, err := img.Layers()
				require.NoError(t, err)
				assert.Len(t, layers, 1)
			}
			regServer := test.NewLocalRegistry(ctx, registry.WithReferrersSupport(true))
			defer regServer.Close()

			u, err := url.Parse(regServer.URL)
			require.NoError(t, err)

			indexName := fmt.Sprintf("%s/repo:root", u.Host)
			output, err := oci.ParseImageSpecs(indexName)
			require.NoError(t, err)
			artifacts, err := manifest.BuildReferringArtifacts()
			require.NoError(t, err)
			err = oci.SaveImagesNoTag(ctx, artifacts, output)
			require.NoError(t, err)
		})
	}
}
