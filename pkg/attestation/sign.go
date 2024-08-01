package attestation

import (
	"context"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/pkg/tlog"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// SignDSSE signs a payload with a given signer and uploads the signature to the transparency log.
func SignDSSE(ctx context.Context, payload []byte, signer dsse.SignerVerifier, opts *SigningOptions) (*Envelope, error) {
	payloadType := intoto.PayloadType
	env := new(Envelope)
	env.Payload = base64Encoding.EncodeToString(payload)
	env.PayloadType = payloadType
	encPayload := dsse.PAE(payloadType, payload)

	// statement message digest
	hash := util.SHA256(encPayload)

	// sign message digest
	sig, err := signer.Sign(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("error signing attestation: %w", err)
	}

	// get Key ID from signer
	keyID, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}

	dsseSig := &Signature{
		KeyID: keyID,
		Sig:   base64Encoding.EncodeToString(sig),
	}
	if !opts.SkipTL {
		ext, err := logSignature(ctx, tlog.GetTL(ctx), &sig, &encPayload, signer)
		if err != nil {
			return nil, fmt.Errorf("failed to log to rekor: %w", err)
		}
		dsseSig.Extension = ext
	}
	// add signature to dsse envelope
	env.Signatures = []*Signature{dsseSig}

	return env, nil
}

// returns a new envelope with the transparency log entry added to the signature extension.
func logSignature(ctx context.Context, t tlog.TL, sig *[]byte, encPayload *[]byte, signer dsse.SignerVerifier) (*Extension, error) {
	// get Key ID from signer
	keyID, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}
	entry, err := t.UploadLogEntry(ctx, keyID, *encPayload, *sig, signer)
	if err != nil {
		return nil, fmt.Errorf("error uploading TL entry: %w", err)
	}
	entryObj, err := t.UnmarshalEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling tl entry: %w", err)
	}
	return &Extension{
		Kind: DockerDSSEExtKind,
		Ext: &DockerDSSEExtension{
			TL: &DockerTLExtension{
				Kind: RekorTLExtKind,
				Data: entryObj, // transparency log entry metadata
			},
		},
	}, nil
}
