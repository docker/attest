package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tlog"
	"github.com/docker/attest/tuf"
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
	Keys    []*KeyMetadata
	KeysMap map[string]*KeyMetadata
)

type SimpleECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	sig       *Signature
	keyMeta   *KeyMetadata
}

// ensure SimpleECDSAVerifier implements dsse.Verifier.
var _ dsse.Verifier = (*SimpleECDSAVerifier)(nil)

func NewSimpleECDSAVerifier(sig *Signature, opts *VerifyOptions) (dsse.Verifier, error) {
	keys := make(map[string]*KeyMetadata, len(opts.Keys))
	for _, key := range opts.Keys {
		keys[key.ID] = key
	}
	keyMeta, ok := keys[sig.KeyID]
	if !ok {
		return nil, fmt.Errorf("error key not found: %s", sig.KeyID)
	}

	if keyMeta.Distrust {
		return nil, fmt.Errorf("key %s is distrusted", keyMeta.ID)
	}
	publicKey, err := signerverifier.ParseECDSAPublicKey([]byte(keyMeta.PEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return &SimpleECDSAVerifier{
		publicKey: publicKey,
		sig:       sig,
		keyMeta:   keyMeta,
	}, nil
}

func (v *SimpleECDSAVerifier) Verify(_ context.Context, data, signature []byte) error {
	// verify payload ecdsa signature
	ok := ecdsa.VerifyASN1(v.publicKey, util.SHA256(data), signature)
	if !ok {
		return fmt.Errorf("payload signature is not valid")
	}

	return nil
}

func (v *SimpleECDSAVerifier) Public() crypto.PublicKey {
	return v.publicKey
}

func (v *SimpleECDSAVerifier) KeyID() (string, error) {
	return v.sig.KeyID, nil
}

type DefaultVerifierFactory struct {
	tufDownloader tuf.Downloader
}

func NewCompositeVerifier(verifiers ...dsse.Verifier) dsse.Verifier {
	return &CompositeVerifier{
		verifiers: verifiers,
	}
}

// must implement dsse.Verifier.
var _ dsse.Verifier = (*CompositeVerifier)(nil)

type CompositeVerifier struct {
	verifiers []dsse.Verifier
}

// KeyID implements dsse.Verifier.
func (c *CompositeVerifier) KeyID() (string, error) {
	return "", fmt.Errorf("unimplemented")
}

// Public implements dsse.Verifier.
func (c *CompositeVerifier) Public() crypto.PublicKey {
	return nil
}

// Verify implements dsse.Verifier.
func (c *CompositeVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	for _, v := range c.verifiers {
		if err := v.Verify(ctx, data, sig); err != nil {
			return err
		}
	}
	return nil
}

// must implement dsse.Verifier.
var _ dsse.Verifier = (*TransparencyLogVerifier)(nil)

type TransparencyLogVerifier struct {
	transparencyLog tlog.TransparencyLog
	sig             *Signature
	keyMeta         *KeyMetadata
	publicKey       crypto.PublicKey
}

func NewTransparencyLogVerifier(sig *Signature, transparencyLog tlog.TransparencyLog, opts *VerifyOptions) (*TransparencyLogVerifier, error) {
	keys := make(map[string]*KeyMetadata, len(opts.Keys))
	for _, key := range opts.Keys {
		keys[key.ID] = key
	}
	keyMeta, ok := keys[sig.KeyID]
	if !ok {
		return nil, fmt.Errorf("error key not found: %s", sig.KeyID)
	}

	if keyMeta.Distrust {
		return nil, fmt.Errorf("key %s is distrusted", keyMeta.ID)
	}
	publicKey, err := signerverifier.ParsePublicKey([]byte(keyMeta.PEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return &TransparencyLogVerifier{
		transparencyLog: transparencyLog,
		sig:             sig,
		keyMeta:         keyMeta,
		publicKey:       publicKey,
	}, nil
}

// KeyID implements dsse.Verifier.
func (v *TransparencyLogVerifier) KeyID() (string, error) {
	return "", fmt.Errorf("unimplemented")
}

// Public implements dsse.Verifier.
func (v *TransparencyLogVerifier) Public() crypto.PublicKey {
	return nil
}

// Verify implements dsse.Verifier.
func (v *TransparencyLogVerifier) Verify(ctx context.Context, data []byte, _ []byte) error {
	if v.sig.Extension == nil || v.sig.Extension.Kind == "" {
		return fmt.Errorf("error missing signature extension")
	}
	if v.sig.Extension.Kind != DockerDSSEExtKind {
		return fmt.Errorf("error unsupported signature extension kind: %s", v.sig.Extension.Kind)
	}

	entry := v.sig.Extension.Ext.TL.Data
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal TL entry: %w", err)
	}

	integratedTime, err := v.transparencyLog.VerifyEntry(ctx, entryBytes)
	if err != nil {
		return fmt.Errorf("TL entry failed verification: %w", err)
	}
	keyMeta := v.keyMeta
	if integratedTime.Before(keyMeta.From) {
		return fmt.Errorf("key %s was not yet valid at TL log time %s (key valid from %s)", keyMeta.ID, integratedTime, keyMeta.From)
	}
	if keyMeta.To != nil && !integratedTime.Before(*keyMeta.To) {
		return fmt.Errorf("key %s was already %s at TL log time %s (key %s at %s)", keyMeta.ID, keyMeta.Status, integratedTime, keyMeta.Status, *keyMeta.To)
	}
	// verify TL entry payload
	encodedPub, err := x509.MarshalPKIXPublicKey(v.publicKey)
	if err != nil {
		return fmt.Errorf("error failed to marshal public key: %w", err)
	}
	err = v.transparencyLog.VerifyEntryPayload(entryBytes, data, encodedPub)
	if err != nil {
		return fmt.Errorf("TL entry failed payload verification: %w", err)
	}
	return nil
}

// NewVerifier creates a new verifier based on the signature and options.
// in the future, we could select verifier based on other inputs from the rego policy (e.g. algorithm).
func (d *DefaultVerifierFactory) NewVerifier(_ context.Context, sig *Signature, opts *VerifyOptions) (dsse.Verifier, error) {
	ecdsaVerifier, err := NewSimpleECDSAVerifier(sig, opts)
	if err != nil {
		return nil, fmt.Errorf("error failed to create ecdsa verifier: %w", err)
	}
	if opts.SkipTL {
		return ecdsaVerifier, nil
	}
	switch opts.TransparencyLog {
	case "":
		fallthrough
	case RekorTransparencyLogKind:
		rekor, err := tlog.NewRekorLogVerifier(d.tufDownloader)
		if err != nil {
			return nil, fmt.Errorf("error failed to create rekor verifier: %w", err)
		}
		tlVerifier, err := NewTransparencyLogVerifier(sig, rekor, opts)
		if err != nil {
			return nil, fmt.Errorf("error failed to create transparency log verifier: %w", err)
		}
		return NewCompositeVerifier(ecdsaVerifier, tlVerifier), nil

	default:
		return nil, fmt.Errorf("unsupported transparency log: %s", opts.TransparencyLog)
	}
}

func NewDefaultVerifierFactory(tufDownloader tuf.Downloader) VerifierFactory {
	return &DefaultVerifierFactory{
		tufDownloader: tufDownloader,
	}
}

type VerifierFactory interface {
	NewVerifier(ctx context.Context, sig *Signature, opts *VerifyOptions) (dsse.Verifier, error)
}

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
		// err := verifySignature(ctx, sig, encPayload, opts)
		// decode signature
		signature, err := base64.StdEncoding.Strict().DecodeString(sig.Sig)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode signature: %w", err)
		}
		if factory == nil {
			// this is without TUF, so rekor public keys can't be looked up in TUF
			factory = NewDefaultVerifierFactory(nil)
		}
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
