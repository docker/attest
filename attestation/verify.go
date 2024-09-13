package attestation

import (
	"context"
	"encoding/base64"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyDSSE(ctx context.Context, factory VerifierFactory, env *Envelope, opts *VerifyOptions) ([]byte, error) {
	// enforce payload type
	if !ValidPayloadType(env.PayloadType) {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	payload, err := base64Encoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error failed to decode payload: %w", err)
	}

	encPayload := dsse.PAE(env.PayloadType, payload)
	// verify signatures and transparency log entry
	for _, sig := range env.Signatures {
		// decode signature
		signature, err := base64.StdEncoding.Strict().DecodeString(sig.Sig)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode signature: %w", err)
		}
		// create a verifier based on inputs from rego policy
		verifier, err := factory.NewVerifier(ctx, sig, opts)
		if err != nil {
			return nil, fmt.Errorf("error failed to create verifier: %w", err)
		}
		err = verifier.Verify(ctx, encPayload, signature)
		if err != nil {
			return nil, err
		}
	}

	return payload, nil
}

func ValidPayloadType(payloadType string) bool {
	return payloadType == intoto.PayloadType || payloadType == ociv1.MediaTypeDescriptor
}
