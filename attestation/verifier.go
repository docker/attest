package attestation

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tlog"
	"github.com/docker/attest/tuf"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func WithTUFDownloader(tufDownloader tuf.Downloader) func(*verifier) {
	return func(r *verifier) {
		r.tufDownloader = tufDownloader
	}
}

type SignatureVerifierFactory func(ctx context.Context, publicKey crypto.PublicKey, opts *VerifyOptions) (dsse.Verifier, error)

func WithSignatureVerifierFactory(factory SignatureVerifierFactory) func(*verifier) {
	return func(r *verifier) {
		r.signatureVerifierFactory = factory
	}
}

func WithLogVerifierFactory(factory LogVerifierFactory) func(*verifier) {
	return func(r *verifier) {
		r.logVerifierFactory = factory
	}
}

type LogVerifierFactory func(ctx context.Context, opts *VerifyOptions) (tlog.TransparencyLog, error)

func NewVerfier(options ...func(*verifier)) (Verifier, error) {
	verifier := &verifier{}
	for _, opt := range options {
		opt(verifier)
	}
	return verifier, nil
}

type Verifier interface {
	GetSignatureVerifier(ctx context.Context, publicKey crypto.PublicKey, opts *VerifyOptions) (dsse.Verifier, error)
	GetLogVerifier(ctx context.Context, opts *VerifyOptions) (tlog.TransparencyLog, error)
	VerifySignature(ctx context.Context, publicKey crypto.PublicKey, data []byte, signature []byte, opts *VerifyOptions) error
	VerifyLog(ctx context.Context, keyMeta *KeyMetadata, data []byte, sig *Signature, opts *VerifyOptions) error
}

// ensure it has all the necessary methods.
var _ Verifier = (*verifier)(nil)

type verifier struct {
	tufDownloader            tuf.Downloader
	signatureVerifierFactory SignatureVerifierFactory
	logVerifierFactory       LogVerifierFactory
}

// GetLogVerifier implements Verifier.
func (v *verifier) GetLogVerifier(ctx context.Context, opts *VerifyOptions) (tlog.TransparencyLog, error) {
	if v.logVerifierFactory != nil {
		return v.logVerifierFactory(ctx, opts)
	}
	if opts.SkipTL {
		return nil, nil
	}
	// TODO support other transparency logs
	var transparencyLog tlog.TransparencyLog
	switch opts.TransparencyLog {
	case "", RekorTransparencyLogKind:
		var err error
		transparencyLog, err = tlog.NewRekorLog(tlog.WithTUFDownloader(v.tufDownloader))
		if err != nil {
			return nil, fmt.Errorf("error failed to create rekor verifier: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transparency log: %s", opts.TransparencyLog)
	}
	return transparencyLog, nil
}

// GetSignatureVerifier implements Verifier.
func (v *verifier) GetSignatureVerifier(ctx context.Context, publicKey crypto.PublicKey, opts *VerifyOptions) (dsse.Verifier, error) {
	if v.signatureVerifierFactory != nil {
		return v.signatureVerifierFactory(ctx, publicKey, opts)
	}
	// TODO: use details from opts to decide which algorithm to use here
	ecdsaVerifier, err := signerverifier.NewECDSAVerifier(publicKey)
	if err != nil {
		return nil, fmt.Errorf("error failed to create ecdsa verifier: %w", err)
	}
	return ecdsaVerifier, nil
}

func (v *verifier) VerifySignature(ctx context.Context, publicKey crypto.PublicKey, data []byte, signature []byte, opts *VerifyOptions) error {
	sigVerifier, err := v.GetSignatureVerifier(ctx, publicKey, opts)
	if err != nil {
		return fmt.Errorf("error failed to get verifier: %w", err)
	}
	return sigVerifier.Verify(ctx, data, signature)
}

func (v *verifier) VerifyLog(ctx context.Context, keyMeta *KeyMetadata, encPayload []byte, sig *Signature, opts *VerifyOptions) error {
	if opts.SkipTL {
		return nil
	}
	if sig.Extension == nil || sig.Extension.Kind == "" {
		return fmt.Errorf("error missing signature extension")
	}
	if sig.Extension.Kind != DockerDSSEExtKind {
		return fmt.Errorf("error unsupported signature extension kind: %s", sig.Extension.Kind)
	}
	transparencyLog, err := v.GetLogVerifier(ctx, opts)
	if err != nil {
		return fmt.Errorf("error failed to get transparency log verifier: %w", err)
	}
	if transparencyLog == nil {
		return fmt.Errorf("error missing transparency log verifier")
	}

	// verify TL entry payload
	publicKey, err := keyMeta.ParsedKey()
	if err != nil {
		return fmt.Errorf("error failed to parse public key: %w", err)
	}
	encodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("error failed to marshal public key: %w", err)
	}
	integratedTime, err := transparencyLog.VerifyEntry(ctx, sig.Extension.Ext.TL, encPayload, encodedPub)
	if err != nil {
		return fmt.Errorf("TL entry failed verification: %w", err)
	}
	if integratedTime.Before(keyMeta.From) {
		return fmt.Errorf("key %s was not yet valid at TL log time %s (key valid from %s)", keyMeta.ID, integratedTime, keyMeta.From)
	}

	// any repo expirey still on the keys must match the 'to' time
	match := false
	if len(keyMeta.Expiries) > 0 {
		// must match at least one
		for _, filter := range keyMeta.Expiries {
			if filter.To != nil && integratedTime.Before(*filter.To) {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("key %s was not valid at TL log time %s", keyMeta.ID, integratedTime)
		}
	} else if keyMeta.To != nil && !integratedTime.Before(*keyMeta.To) {
		return fmt.Errorf("key %s was already %s at TL log time %s (key %s at %s)", keyMeta.ID, keyMeta.Status, integratedTime, keyMeta.Status, *keyMeta.To)
	}
	return nil
}
