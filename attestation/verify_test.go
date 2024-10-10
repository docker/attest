package attestation_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestValidPayloadType(t *testing.T) {
	testCases := []struct {
		name        string
		payloadType string
		expected    bool
	}{
		{"valid in-toto payload type", intoto.PayloadType, true},
		{"valid oci descriptor payload type", ociv1.MediaTypeDescriptor, true},
		{"invalid payload type", "application/vnd.test.fail", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equalf(t, tc.expected, attestation.ValidPayloadType(tc.payloadType), "expected %v for payload type %s", tc.expected, tc.payloadType)
		})
	}
}

func TestVerifyUnsignedAttestation(t *testing.T) {
	ctx, _ := test.Setup(t)

	payload := []byte("payload")
	env := &attestation.Envelope{
		// no signatures
		Signatures:  []*attestation.Signature{},
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: intoto.PayloadType,
	}
	opts := &attestation.VerifyOptions{}
	_, err := attestation.VerifyDSSE(ctx, nil, env, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no signatures")
}

func TestEnsureValid(t *testing.T) {
	now := time.Now()
	keyFrom := now.Add(-time.Hour)
	keyTo := now.Add(time.Hour)
	justBefore := keyTo.Add(-time.Second)
	// justAfter := after.Add(time.Second)

	tests := []struct {
		name           string
		imageName      string
		platform       *v1.Platform
		key            *attestation.KeyMetadata
		wantErr        bool
		expired        bool
		integratedTime *time.Time
	}{
		// {name: "no custom validity", key: &attestation.KeyMetadata{}},
		// {name: "no custom validity", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{},
		// }},
		// {name: "malformed pattern", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{
		// 		{Patterns: []string{"[]"}},
		// 	},
		// }, wantErr: true},
		// {name: "missing pattern", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{
		// 		{To: &now},
		// 	},
		// }, wantErr: true},
		// {name: "no matching image", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{
		// 		{Patterns: []string{"bar"}, To: &now},
		// 	},
		// }, wantErr: true},
		// {name: "matching image, no platforms", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{
		// 		{Patterns: []string{"foo"}, To: &justBefore},
		// 	},
		// }},
		// {name: "matching image, wrong platform", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{
		// 		{Patterns: []string{"foo"}, Platforms: []string{"linux/arm64"}, To: &now},
		// 	},
		// }, wantErr: true},
		// {name: "matching image, matching platform", key: &attestation.KeyMetadata{
		// 	ValidityRanges: []*attestation.ValidityRange{
		// 		{Patterns: []string{"foo"}, Platforms: []string{"linux/amd64"}, To: &justBefore},
		// 	},
		// }},
		{name: "matching canonical image, matching platform", key: &attestation.KeyMetadata{
			ValidityRanges: []*attestation.ValidityRange{
				{Patterns: []string{"^docker.io/library/foo$"}, Platforms: []string{"linux/amd64"}, To: &justBefore},
			},
		}},
		{name: "matching image, matching platform (on of many)", key: &attestation.KeyMetadata{
			ValidityRanges: []*attestation.ValidityRange{
				{Patterns: []string{"foo"}, Platforms: []string{"linux/amd64", "linux/arm64"}, To: &justBefore},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageName := tt.imageName
			if imageName == "" {
				imageName = "foo"
			}
			platform := tt.platform
			if platform == nil {
				platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
			}
			tt.key.ID = "TEST_KEY"
			tt.key.From = &keyFrom
			tt.key.To = &keyTo
			integratedTime := tt.integratedTime
			if integratedTime == nil {
				integratedTime = &now
			}
			err := tt.key.EnsureValid(imageName, platform, integratedTime)
			if !tt.wantErr {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

type NullAttestationResolver struct {
	called    bool
	imageName string
	platform  *v1.Platform
}

func (r *NullAttestationResolver) ImageName(_ context.Context) (string, error) {
	return r.imageName, nil
}

func (r *NullAttestationResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	if r.platform != nil {
		return r.platform, nil
	}
	return v1.ParsePlatform("")
}

func (r *NullAttestationResolver) ImageDescriptor(_ context.Context) (*v1.Descriptor, error) {
	return nil, nil
}

func (r *NullAttestationResolver) Attestations(_ context.Context, _ string) ([]*attestation.EnvelopeReference, error) {
	r.called = true
	return nil, nil
}
