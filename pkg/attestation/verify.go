package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/pkg/signerverifier"
	"github.com/docker/attest/pkg/tlog"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type KeyMetadata struct {
	ID            string     `json:"id"`
	PEM           string     `json:"key"`
	From          time.Time  `json:"from"`
	To            *time.Time `json:"to"`
	Status        string     `json:"status"`
	SigningFormat string     `json:"signing-format"`
	Distrust      bool       `json:"distrust,omitempty"`
}

type (
	Keys    []KeyMetadata
	KeysMap map[string]KeyMetadata
)

func VerifyDSSE(ctx context.Context, env *Envelope, opts *VerifyOptions) ([]byte, error) {
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
		err := verifySignature(ctx, sig, encPayload, opts)
		if err != nil {
			return nil, err
		}
	}

	return payload, nil
}

func verifySignature(ctx context.Context, sig Signature, payload []byte, opts *VerifyOptions) error {
	keys := make(map[string]KeyMetadata, len(opts.Keys))
	for _, key := range opts.Keys {
		keys[key.ID] = key
	}
	keyMeta, ok := keys[sig.KeyID]
	if !ok {
		return fmt.Errorf("error key not found: %s", sig.KeyID)
	}

	if keyMeta.Distrust {
		return fmt.Errorf("key %s is distrusted", keyMeta.ID)
	}
	// TODO: this is unmarshalling with MarshalPKIXPublicKey only for us to marshal it again
	publicKey, err := signerverifier.Parse([]byte(keyMeta.PEM))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if !opts.SkipTL {
		t := tlog.GetTL(ctx)

		if sig.Extension.Kind == "" {
			return fmt.Errorf("error missing signature extension kind")
		}
		if sig.Extension.Kind != DockerDsseExtKind {
			return fmt.Errorf("error unsupported signature extension kind: %s", sig.Extension.Kind)
		}

		// verify TL entry
		if sig.Extension.Ext.Tl.Kind != RekorTlExtKind {
			return fmt.Errorf("error unsupported TL extension kind: %s", sig.Extension.Ext.Tl.Kind)
		}
		entry := sig.Extension.Ext.Tl.Data
		entryBytes, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal TL entry: %w", err)
		}

		integratedTime, err := t.VerifyLogEntry(ctx, entryBytes)
		if err != nil {
			return fmt.Errorf("TL entry failed verification: %w", err)
		}
		if integratedTime.Before(keyMeta.From) {
			return fmt.Errorf("key %s was not yet valid at TL log time %s (key valid from %s)", keyMeta.ID, integratedTime, keyMeta.From)
		}
		if keyMeta.To != nil && !integratedTime.Before(*keyMeta.To) {
			return fmt.Errorf("key %s was already %s at TL log time %s (key %s at %s)", keyMeta.ID, keyMeta.Status, integratedTime, keyMeta.Status, *keyMeta.To)
		}
		// verify TL entry payload
		encodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("error failed to marshal public key: %w", err)
		}
		err = t.VerifyEntryPayload(entryBytes, payload, encodedPub)
		if err != nil {
			return fmt.Errorf("TL entry failed payload verification: %w", err)
		}
	}

	// decode signature
	signature, err := base64.StdEncoding.Strict().DecodeString(sig.Sig)
	if err != nil {
		return fmt.Errorf("error failed to decode signature: %w", err)
	}
	// verify payload ecdsa signature
	ok = ecdsa.VerifyASN1(publicKey, util.SHA256(payload), signature)
	if !ok {
		return fmt.Errorf("payload signature is not valid")
	}

	return nil
}

func ValidPayloadType(payloadType string) bool {
	return payloadType == intoto.PayloadType || payloadType == ociv1.MediaTypeDescriptor
}
