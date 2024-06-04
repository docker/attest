package attestation

import (
	"context"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// SignDSSE signs a payload with a given signer and uploads the signature to the transparency log
func SignDSSE(ctx context.Context, payload []byte, payloadType string, signer dsse.SignerVerifier) (*Envelope, error) {

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
	keyId, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}

	// add signature to dsse envelope
	env.Signatures = append(env.Signatures, Signature{
		KeyID: keyId,
		Sig:   base64Encoding.EncodeToString(sig),
	})

	return env, nil
}

// returns a new envelope with the transparency log entry added to the signature extension
func LogSignature(ctx context.Context, t tlog.TL, env *Envelope, signer dsse.SignerVerifier) (*Envelope, error) {
	// get Key ID from signer
	keyId, err := signer.KeyID()
	if err != nil {
		return nil, fmt.Errorf("error getting public key ID: %w", err)
	}

	var sigs []Signature
	for _, s := range env.Signatures {
		fakeEnv := dsse.Envelope{
			Payload: env.Payload,
		}
		encPayload, err := fakeEnv.DecodeB64Payload()
		if err != nil {
			return nil, fmt.Errorf("error decoding payload: %w", err)
		}
		sig, err := base64Encoding.DecodeString(s.Sig)
		if err != nil {
			return nil, fmt.Errorf("error decoding signature: %w", err)
		}
		entry, err := t.UploadLogEntry(ctx, keyId, encPayload, sig, signer)
		if err != nil {
			return nil, fmt.Errorf("error uploading TL entry: %w", err)
		}
		entryObj, err := t.UnmarshalEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling tl entry: %w", err)
		}
		newsig := Signature{
			KeyID: s.KeyID,
			Sig:   s.Sig,
			Extension: Extension{
				Kind: DockerDsseExtKind,
				Ext: DockerDsseExtension{
					Tl: DockerTlExtension{
						Kind: RekorTlExtKind,
						Data: entryObj, // transparency log entry metadata
					},
				},
			},
		}
		sigs = append(sigs, newsig)
	}
	newEnv := &Envelope{
		Payload:     env.Payload,
		PayloadType: env.PayloadType,
		Signatures:  sigs,
	}
	return newEnv, nil
}
