package attestation

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/docker/attest/tlog"
	"github.com/docker/attest/tuf"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func WithTUFDownloader(tufDownloader tuf.Downloader) func(*verifier) {
	return func(r *verifier) {
		r.tufDownloader = tufDownloader
	}
}

func WithTransparencyLog(log tlog.TransparencyLog) func(*verifier) {
	return func(r *verifier) {
		r.transparencyLog = log
	}
}

func NewVerfier(options ...func(*verifier)) (Verifier, error) {
	verifier := &verifier{}
	for _, opt := range options {
		opt(verifier)
	}
	return verifier, nil
}

type Verifier interface {
	VerifySignature(ctx context.Context, publicKey crypto.PublicKey, data []byte, signature []byte, opts *VerifyOptions) error
	VerifyLog(ctx context.Context, keyMeta *KeyMetadata, data []byte, sig *Signature, opts *VerifyOptions) error
}

// ensure it has all the necessary methods.
var _ Verifier = (*verifier)(nil)

type verifier struct {
	tufDownloader     tuf.Downloader
	signatureVerifier dsse.Verifier
	transparencyLog   tlog.TransparencyLog
}

func (av *verifier) VerifySignature(ctx context.Context, publicKey crypto.PublicKey, data []byte, signature []byte, _ *VerifyOptions) error {
	// TODO: use details from opts to decide which algorithm to use here
	ecdsaVerifier, err := NewECDSAVerifier(publicKey)
	if err != nil {
		return fmt.Errorf("error failed to create ecdsa verifier: %w", err)
	}
	return ecdsaVerifier.Verify(ctx, data, signature)
}

func (av *verifier) VerifyLog(ctx context.Context, keyMeta *KeyMetadata, data []byte, sig *Signature, opts *VerifyOptions) error {
	if opts.SkipTL {
		return nil
	}

	// TODO support other transparency logs
	var transparencyLog tlog.TransparencyLog = av.transparencyLog
	if transparencyLog == nil {
		switch opts.TransparencyLog {
		case "":
			fallthrough
		case RekorTransparencyLogKind:
			var err error
			transparencyLog, err = tlog.NewRekorLogVerifier(av.tufDownloader)
			if err != nil {
				return fmt.Errorf("error failed to create rekor verifier: %w", err)
			}

		default:
			return fmt.Errorf("unsupported transparency log: %s", opts.TransparencyLog)
		}
	}

	if sig.Extension == nil || sig.Extension.Kind == "" {
		return fmt.Errorf("error missing signature extension")
	}
	if sig.Extension.Kind != DockerDSSEExtKind {
		return fmt.Errorf("error unsupported signature extension kind: %s", sig.Extension.Kind)
	}

	entry := sig.Extension.Ext.TL.Data
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal TL entry: %w", err)
	}

	integratedTime, err := transparencyLog.VerifyEntry(ctx, entryBytes)
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
	encodedPub, err := x509.MarshalPKIXPublicKey(av.signatureVerifier.Public())
	if err != nil {
		return fmt.Errorf("error failed to marshal public key: %w", err)
	}
	err = transparencyLog.VerifyEntryPayload(entryBytes, data, encodedPub)
	if err != nil {
		return fmt.Errorf("TL entry failed payload verification: %w", err)
	}
	return nil
}
