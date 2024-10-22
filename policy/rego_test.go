/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package policy

import (
	"context"
	"testing"

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

func TestReproGitChecksum(t *testing.T) {
	paths := []string{"testdata/policies/test/git_checksum"}
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
	assert.Truef(t, results[0].Pass(), "expected result 1 to pass, got failure at %v", results[0].Location)
}

func buffer[T any](ch chan T) []T {
	var out []T
	for v := range ch {
		out = append(out, v)
	}
	return out
}

type NullAttestationResolver struct {
	called bool
}

func (r *NullAttestationResolver) ImageName(_ context.Context) (string, error) {
	return "", nil
}

func (r *NullAttestationResolver) ImagePlatform(_ context.Context) (*v1.Platform, error) {
	return v1.ParsePlatform("")
}

func (r *NullAttestationResolver) ImageDescriptor(_ context.Context) (*v1.Descriptor, error) {
	return nil, nil
}

func (r *NullAttestationResolver) Attestations(_ context.Context, _ string) ([]*attestation.EnvelopeReference, error) {
	r.called = true
	return nil, nil
}
