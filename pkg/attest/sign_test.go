package attest

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/docker/attest/internal/test"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/stretchr/testify/assert"
)

var (
	UnsignedTestImage = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")
	NoProvenanceImage = filepath.Join("..", "..", "test", "testdata", "no-provenance-image")
	LocalPolicyDir    = filepath.Join("..", "..", "test", "testdata", "local-policy")
	TestTempDir       = "attest-sign-test"
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

		{"signed replaced (does nothing)", UnsignedTestImage, 0, 6, true},
		{"without replace", UnsignedTestImage, 4, 6, false},
		// image without provenance doesn't fail
		{"no provenance (replace)", NoProvenanceImage, 0, 4, true},
		{"no provenance (no replace)", NoProvenanceImage, 2, 4, false},
	}
	policyResolver := &policy.PolicyOptions{
		LocalPolicyDir: LocalPolicyDir,
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := test.CreateTempDir(t, "", TestTempDir)
			outputLayout := tempDir
			opts := &SigningOptions{
				Replace: tc.replace,
				VSAOptions: &attestation.VSAOptions{
					BuildLevel: "SLSA_BUILD_LEVEL_3",
					PolicyURI:  "https://docker.com/attest/policy",
					VerifierID: "https://docker.com",
				},
			}
			attIdx, err := oci.AttestationIndexFromPath(tc.TestImage)
			assert.NoError(t, err)
			signedIndex, err := SignIndexAttestations(ctx, attIdx.Index, signer, opts)
			assert.NoError(t, err)

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
			assert.NoError(t, err)

			resolver := &oci.OCILayoutResolver{
				Path:     outputLayout,
				Platform: "",
			}
			policy, err := Verify(ctx, policyResolver, resolver)
			assert.NoError(t, err)
			assert.Truef(t, policy, "Policy should have been found")

			mt, _ := attestation.DSSEMediaType(attestation.VSAPredicateType)
			vsas, err := test.ExtractAnnotatedStatements(tempDir, mt)
			assert.NoError(t, err)
			assert.Equalf(t, len(vsas), 2, "expected %d vsa statement, got %d", 2, len(vsas))
			var allEnvelopes []*test.AnnotatedStatement
			for _, predicate := range []string{intoto.PredicateSPDX, v02.PredicateSLSAProvenance, attestation.VSAPredicateType} {
				mt, _ := attestation.DSSEMediaType(predicate)
				statements, err := test.ExtractAnnotatedStatements(tempDir, mt)
				assert.NoError(t, err)
				allEnvelopes = append(allEnvelopes, statements...)

				for _, stmt := range statements {
					assert.Equalf(t, predicate, stmt.Annotations[oci.InTotoPredicateType], "expected predicate-type annotation to be set to %s, got %s", predicate, stmt.Annotations[oci.InTotoPredicateType])
					assert.Equalf(t, LifecycleStageExperimental, stmt.Annotations[InTotoReferenceLifecycleStage], "expected reference lifecycle stage annotation to be set to %s, got %s", LifecycleStageExperimental, stmt.Annotations[InTotoReferenceLifecycleStage])
				}
			}
			assert.Equalf(t, tc.expectedAttestations, len(allEnvelopes), "expected %d attestations, got %d", tc.expectedAttestations, len(allEnvelopes))
			statements, err := test.ExtractAnnotatedStatements(tempDir, intoto.PayloadType)
			assert.NoError(t, err)
			assert.Equalf(t, tc.expectedStatements, len(statements), "expected %d statement, got %d", tc.expectedStatements, len(statements))
		})
	}
}

func TestAddSignedLayerAnnotations(t *testing.T) {
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
			signedLayer := static.NewLayer(data, types.MediaType(intoto.PayloadType))
			signedLayers := []mutate.Addendum{
				{
					Layer:       signedLayer,
					Annotations: map[string]string{"test": "test"},
				},
			}
			data = []byte("test")
			testLayer := static.NewLayer(data, types.MediaType(intoto.PayloadType))
			mediaType := types.OCIManifestSchema1
			img := empty.Image
			opts := &SigningOptions{
				Replace: tc.replace,
			}
			newImg, err := addSignedLayers(signedLayers, []v1.Layer{testLayer}, mediaType, img, opts)
			assert.NoError(t, err)
			mf, _ := newImg.RawManifest()
			type Annotations struct {
				Annotations map[string]string `json:"annotations"`
			}
			type Layers struct {
				Layers []Annotations `json:"layers"`
			}
			l := &Layers{}
			err = json.Unmarshal(mf, l)
			assert.NoError(t, err)
			_, ok := l.Layers[0].Annotations["test"]
			assert.Truef(t, ok, "missing annotations")
		})
	}
}
