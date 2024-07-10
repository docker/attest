package attest

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/mirror"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	UnsignedTestImage   = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
	NoProvenanceImage   = filepath.Join("..", "..", "test", "testdata", "no-provenance-image")
	PassPolicyDir       = filepath.Join("..", "..", "test", "testdata", "local-policy-pass")
	PassMirrorPolicyDir = filepath.Join("..", "..", "test", "testdata", "local-policy-mirror")
	PassNoTLPolicyDir   = filepath.Join("..", "..", "test", "testdata", "local-policy-no-tl")
	FailPolicyDir       = filepath.Join("..", "..", "test", "testdata", "local-policy-fail")
	TestTempDir         = "attest-sign-test"
)

func TestSignVerifyOCILayout(t *testing.T) {
	ctx, signer := test.Setup(t)

	testCases := []struct {
		name                 string
		TestImage            string
		expectedStatements   int
		expectedAttestations int
		replace              bool
	}{
		{"signed replaced", UnsignedTestImage, 0, 4, true},
		{"without replace", UnsignedTestImage, 4, 4, false},
		// image without provenance doesn't fail
		{"no provenance (replace)", NoProvenanceImage, 0, 2, true},
		{"no provenance (no replace)", NoProvenanceImage, 2, 2, false},
	}
	policyOpts := &policy.PolicyOptions{
		LocalPolicyDir: PassPolicyDir,
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputLayout := test.CreateTempDir(t, "", TestTempDir)
			opts := &attestation.SigningOptions{}
			attIdx, err := oci.IndexFromPath(tc.TestImage)
			require.NoError(t, err)
			signedManifests, err := SignStatements(ctx, attIdx.Index, signer, opts)
			require.NoError(t, err)
			signedIndex := attIdx.Index
			signedIndex, err = attestation.UpdateIndexImages(signedIndex, signedManifests, attestation.WithReplacedLayers(tc.replace))
			require.NoError(t, err)
			// output signed attestations
			idx := v1.ImageIndex(empty.Index)
			idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
				Add: signedIndex,
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{
						oci.OciReferenceTarget: attIdx.Name,
					},
				},
			})
			_, err = layout.Write(outputLayout, idx)
			require.NoError(t, err)
			src, err := oci.ParseImageSpec("oci://" + outputLayout)
			require.NoError(t, err)
			policy, err := Verify(ctx, src, policyOpts)
			require.NoError(t, err)
			assert.Equalf(t, OutcomeSuccess, policy.Outcome, "Policy should have been found")

			var allEnvelopes []*test.AnnotatedStatement
			for _, predicate := range []string{intoto.PredicateSPDX, v02.PredicateSLSAProvenance, attestation.VSAPredicateType} {
				mt, _ := attestation.DSSEMediaType(predicate)
				statements, err := test.ExtractAnnotatedStatements(outputLayout, mt)
				require.NoError(t, err)
				allEnvelopes = append(allEnvelopes, statements...)

				for _, stmt := range statements {
					assert.Equalf(t, predicate, stmt.Annotations[attestation.InTotoPredicateType], "expected predicate-type annotation to be set to %s, got %s", predicate, stmt.Annotations[attestation.InTotoPredicateType])
					assert.Equalf(t, attestation.LifecycleStageExperimental, stmt.Annotations[attestation.InTotoReferenceLifecycleStage], "expected reference lifecycle stage annotation to be set to %s, got %s", attestation.LifecycleStageExperimental, stmt.Annotations[attestation.InTotoReferenceLifecycleStage])
				}
			}
			assert.Equalf(t, tc.expectedAttestations, len(allEnvelopes), "expected %d attestations, got %d", tc.expectedAttestations, len(allEnvelopes))
			statements, err := test.ExtractAnnotatedStatements(outputLayout, intoto.PayloadType)
			require.NoError(t, err)
			assert.Equalf(t, tc.expectedStatements, len(statements), "expected %d statement, got %d", tc.expectedStatements, len(statements))
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
			originalLayer := &attestation.AttestationLayer{
				Layer: testLayer,
				Statement: &intoto.Statement{
					StatementHeader: intoto.StatementHeader{
						PredicateType: attestation.VSAPredicateType,
					},
				},
				Annotations: map[string]string{"test": "test"},
			}

			manifest := &attestation.AttestationManifest{
				OriginalDescriptor: &v1.Descriptor{
					MediaType: mediaType,
				},
				OriginalLayers: []*attestation.AttestationLayer{
					originalLayer,
				},
				SubjectDescriptor: &v1.Descriptor{},
			}
			err := manifest.AddAttestation(ctx, signer, originalLayer.Statement, opts)

			newImg, err := manifest.BuildAttestationImage(attestation.WithReplacedLayers(tc.replace))
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
			manifest, err := NewAttestationManifest(subject)
			require.NoError(t, err)
			err = manifest.AddAttestation(ctx, signer, statement, opts)
			require.NoError(t, err)

			err = manifest.AddAttestation(ctx, signer, statement2, opts)
			require.NoError(t, err)

			// fake that the manfifest was loaded from a real image
			manifest.OriginalLayers = manifest.SignedLayers
			envelopes, err := oci.ExtractEnvelopes(manifest, attestation.VSAPredicateType)
			require.NoError(t, err)
			assert.Len(t, envelopes, 2)

			newImg, err := manifest.BuildAttestationImage(attestation.WithReplacedLayers(tc.replace))
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
				assert.Equal(t, "application/vnd.in-toto+json", mf.ArtifactType)
				assert.Equal(t, subject.MediaType, mf.MediaType)
				assert.Equal(t, empty, mf.Config.MediaType)
				assert.Equal(t, int64(2), mf.Config.Size)
				assert.Equal(t, "e30=", string(mf.Config.Data))
				layers, err := img.Layers()
				require.NoError(t, err)
				assert.Len(t, layers, 1)
			}
			server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
			defer server.Close()

			u, err := url.Parse(server.URL)
			require.NoError(t, err)

			indexName := fmt.Sprintf("%s/repo:root", u.Host)
			output, err := oci.ParseImageSpecs(indexName)
			err = mirror.SaveReferrers(manifest, output)
			require.NoError(t, err)
		})
	}
}
