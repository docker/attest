package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tlog"
	"github.com/docker/attest/tuf"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type ecdsaVerifier struct {
	publicKey *ecdsa.PublicKey
	sig       *Signature
	keyMeta   *KeyMetadata
}

// ensure ECDSAVerifier implements dsse.Verifier.
var _ dsse.Verifier = (*ecdsaVerifier)(nil)

func NewECDSAVerifier(sig *Signature, opts *VerifyOptions) (dsse.Verifier, error) {
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
	return &ecdsaVerifier{
		publicKey: publicKey,
		sig:       sig,
		keyMeta:   keyMeta,
	}, nil
}

func (v *ecdsaVerifier) Verify(_ context.Context, data, signature []byte) error {
	// verify payload ecdsa signature
	ok := ecdsa.VerifyASN1(v.publicKey, util.SHA256(data), signature)
	if !ok {
		return fmt.Errorf("payload signature is not valid")
	}

	return nil
}

func (v *ecdsaVerifier) Public() crypto.PublicKey {
	return v.publicKey
}

func (v *ecdsaVerifier) KeyID() (string, error) {
	return v.sig.KeyID, nil
}

type defaultVerifierFactory struct {
	tufDownloader tuf.Downloader
}

// must implement dsse.Verifier.
var _ dsse.Verifier = (*transparencyLogVerifier)(nil)

type transparencyLogVerifier struct {
	transparencyLog tlog.TransparencyLog
	sig             *Signature
	keyMeta         *KeyMetadata
	publicKey       crypto.PublicKey
}

func NewTransparencyLogVerifier(sig *Signature, transparencyLog tlog.TransparencyLog, opts *VerifyOptions) (dsse.Verifier, error) {
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
	return &transparencyLogVerifier{
		transparencyLog: transparencyLog,
		sig:             sig,
		keyMeta:         keyMeta,
		publicKey:       publicKey,
	}, nil
}

// KeyID implements dsse.Verifier.
func (v *transparencyLogVerifier) KeyID() (string, error) {
	// TODO implement.
	return "", fmt.Errorf("unimplemented")
}

// Public implements dsse.Verifier.
func (v *transparencyLogVerifier) Public() crypto.PublicKey {
	// TODO implement.
	return nil
}

// Verify implements dsse.Verifier.
func (v *transparencyLogVerifier) Verify(ctx context.Context, data []byte, _ []byte) error {
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
func (d *defaultVerifierFactory) NewVerifier(_ context.Context, sig *Signature, opts *VerifyOptions) (dsse.Verifier, error) {
	ecdsaVerifier, err := NewECDSAVerifier(sig, opts)
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
		return signerverifier.NewCompositeVerifier(ecdsaVerifier, tlVerifier), nil

	default:
		return nil, fmt.Errorf("unsupported transparency log: %s", opts.TransparencyLog)
	}
}

func NewTUFVerifierFactory(tufDownloader tuf.Downloader) VerifierFactory {
	return &defaultVerifierFactory{
		tufDownloader: tufDownloader,
	}
}

func NewVerifierFactory() VerifierFactory {
	return &defaultVerifierFactory{}
}

type VerifierFactory interface {
	NewVerifier(ctx context.Context, sig *Signature, opts *VerifyOptions) (dsse.Verifier, error)
}
