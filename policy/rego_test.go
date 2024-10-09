package policy

import (
	"context"
	"testing"
	"time"

	"github.com/docker/attest/attestation"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/open-policy-agent/opa/tester"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy(t *testing.T) {
	paths := []string{"testdata/policies/test/fetch"}
	modules, store, err := tester.Load(paths, nil)
	require.NoError(t, err)
	resolver := &NullAttestationResolver{}

	opts := NewRegoFunctionOptions(resolver, nil)
	ctx := context.Background()
	ch, err := tester.NewRunner().
		SetStore(store).
		AddCustomBuiltins(RegoFunctions(opts)).
		CapturePrintOutput(true).
		RaiseBuiltinErrors(true).
		EnableTracing(true).
		SetModules(modules).
		RunTests(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	results := buffer(ch)
	assert.Equalf(t, 1, len(results), "expected 1 results, got %d", len(results))
	assert.Truef(t, results[0].Pass(), "expected result 1 to pass, got %v", results[0])
	assert.True(t, resolver.called)
}

func TestPolicyDefParse(t *testing.T) {
	paths := []string{"testdata/policies/test/def_parse"}
	modules, store, err := tester.Load(paths, nil)
	require.NoError(t, err)
	resolver := &NullAttestationResolver{}

	opts := NewRegoFunctionOptions(resolver, nil)
	ctx := context.Background()
	ch, err := tester.NewRunner().
		SetStore(store).
		AddCustomBuiltins(RegoFunctions(opts)).
		CapturePrintOutput(true).
		RaiseBuiltinErrors(true).
		EnableTracing(true).
		SetModules(modules).
		RunTests(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, err)
	results := buffer(ch)
	t.Log(string(results[0].Output))
	assert.Equalf(t, 1, len(results), "expected 1 results, got %d", len(results))
	assert.Truef(t, results[0].Pass(), "expected result 1 to pass, got %v", results[0].Location)
}

func buffer[T any](ch chan T) []T {
	var out []T
	for v := range ch {
		out = append(out, v)
	}
	return out
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

func TestRegoFnOpts_filterRepoExpiries(t *testing.T) {
	now := time.Now()
	validTime := now.Add(-time.Hour)
	tests := []struct {
		name      string
		imageName string
		key       *attestation.KeyMetadata
		wantErr   bool
		expired   bool
	}{
		{name: "no custom expiry", key: &attestation.KeyMetadata{}},
		{name: "no custom expiry", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{},
		}},
		{name: "malformed pattern", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"[]"}, To: &now},
			},
		}, wantErr: true},
		{name: "missing pattern", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{To: &now},
			},
		}, wantErr: true},
		{name: "no matching image", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"bar"}, To: &now},
			},
		}, expired: true},
		{name: "matching image, no platforms", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"foo"}, To: &now},
			},
		}},
		{name: "matching image, wrong platform", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"foo"}, Platforms: []string{"linux/arm64"}, To: &now},
			},
		}, expired: true},
		{name: "matching image, matching platform", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"foo"}, Platforms: []string{"linux/amd64"}, To: &now},
			},
		}},
		{name: "matching canonical image, matching platform", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"^docker.io/library/foo$"}, Platforms: []string{"linux/amd64"}, To: &now},
			},
		}},
		{name: "matching image, matching platform (on of many)", key: &attestation.KeyMetadata{
			Expiries: []*attestation.KeyExpiry{
				{Patterns: []string{"foo"}, Platforms: []string{"linux/amd64", "linux/arm64"}, To: &now},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageName := tt.imageName
			if imageName == "" {
				imageName = "foo"
			}
			resolver := &NullAttestationResolver{
				imageName: imageName,
				platform:  &v1.Platform{OS: "linux", Architecture: "amd64"},
			}

			opts := &attestation.VerifyOptions{
				Keys: attestation.Keys{tt.key},
			}
			if err := opts.ProcessKeys(context.Background(), resolver); (err != nil) != tt.wantErr {
				t.Fatalf("RegoFnOpts.filterRepoExpiries() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				switch {
				case tt.expired:
					assert.Error(t, opts.Keys[0].EnsureValid(&validTime))
				default:
					assert.NoError(t, opts.Keys[0].EnsureValid(&validTime))
				}
			}
		})
	}
}
