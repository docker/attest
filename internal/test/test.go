package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/signerverifier"
	"github.com/docker/attest/pkg/tlog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	USE_MOCK_TL     = true
	USE_MOCK_KMS    = true
	USE_MOCK_POLICY = true

	AwsRegion    = "us-east-1"
	AwsKmsKeyArn = "arn:aws:kms:us-east-1:175142243308:alias/doi-signing" // sandbox
)

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

func Setup(t *testing.T) (context.Context, dsse.SignerVerifier) {
	var tl tlog.TL
	if USE_MOCK_TL {
		tl = tlog.GetMockTL()
	} else {
		tl = &tlog.RekorTL{}
	}

	ctx := tlog.WithTL(context.Background(), tl)

	var policyEvaluator policy.PolicyEvaluator
	if USE_MOCK_POLICY {
		policyEvaluator = policy.GetMockPolicy()
	} else {
		policyEvaluator = policy.NewRegoEvaluator(true)
	}

	ctx = policy.WithPolicyEvaluator(ctx, policyEvaluator)

	var signer dsse.SignerVerifier
	var err error
	if USE_MOCK_KMS {
		signer, err = GetMockSigner(ctx)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		signer, err = signerverifier.GetAWSSigner(ctx, AwsKmsKeyArn, AwsRegion)
		if err != nil {
			t.Fatal(err)
		}
	}

	return ctx, signer
}

type AnnotatedStatement struct {
	OCIDescriptor   *v1.Descriptor
	InTotoStatement *intoto.Statement
	Annotations     map[string]string
}

func ExtractStatementsFromIndex(idx v1.ImageIndex, mediaType string) ([]*AnnotatedStatement, error) {
	mfs2, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to extract IndexManifest from ImageIndex: %w", err)
	}

	var statements []*AnnotatedStatement

	for _, mf := range mfs2.Manifests {
		if mf.Annotations[attestation.DockerReferenceType] != "attestation-manifest" {
			continue
		}

		attestationImage, err := idx.Image(mf.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to extract attestation image with digest %s: %w", mf.Digest.String(), err)
		}
		layers, err := attestationImage.Layers()
		if err != nil {
			return nil, fmt.Errorf("failed to extract layers from attestation image: %w", err)
		}

		for _, layer := range layers {
			// parse layer blob as json
			mt, err := layer.MediaType()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer media type: %w", err)
			}

			if string(mt) != mediaType {
				continue
			}
			r, err := layer.Uncompressed()
			if err != nil {
				return nil, fmt.Errorf("failed to get layer contents: %w", err)
			}
			defer r.Close()
			intotoStatement := new(intoto.Statement)
			var desc *v1.Descriptor
			if strings.HasSuffix(string(mt), "+dsse") {
				env := new(attestation.Envelope)
				err = json.NewDecoder(r).Decode(env)
				if err != nil {
					return nil, fmt.Errorf("failed to decode env: %w", err)
				}
				payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to decode payload: %w", err)
				}
				err = json.Unmarshal([]byte(payload), intotoStatement)
				if err != nil {
					return nil, fmt.Errorf("failed to decode %s statement: %w", mediaType, err)
				}
			} else {
				desc := new(v1.Descriptor)
				err = json.NewDecoder(r).Decode(desc)
				if err != nil {
					return nil, fmt.Errorf("failed to decode statement: %w", err)
				}
			}

			layerDesc, err := partial.Descriptor(layer)
			if err != nil {
				return nil, fmt.Errorf("failed to get descriptor for layer: %w", err)
			}
			annotations := make(map[string]string)
			for k, v := range layerDesc.Annotations {
				annotations[k] = v
			}
			statements = append(statements, &AnnotatedStatement{
				OCIDescriptor:   desc,
				InTotoStatement: intotoStatement,
				Annotations:     annotations,
			})
		}
	}
	return statements, nil
}

func ExtractAnnotatedStatements(path string, mediaType string) ([]*AnnotatedStatement, error) {
	idx, err := layout.ImageIndexFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load image index: %w", err)
	}

	idxm, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %w", err)
	}
	idxDigest := idxm.Manifests[0].Digest

	mfs, err := idx.ImageIndex(idxDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ImageIndex for digest %s: %w", idxDigest.String(), err)
	}
	return ExtractStatementsFromIndex(mfs, mediaType)
}
