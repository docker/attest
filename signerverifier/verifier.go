package signerverifier

import (
	"context"
	"crypto"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func NewCompositeVerifier(verifiers ...dsse.Verifier) dsse.Verifier {
	return &compositeVerifier{
		verifiers: verifiers,
	}
}

// must implement dsse.Verifier.
var _ dsse.Verifier = (*compositeVerifier)(nil)

type compositeVerifier struct {
	verifiers []dsse.Verifier
}

// KeyID implements dsse.Verifier.
func (c *compositeVerifier) KeyID() (string, error) {
	return "", fmt.Errorf("unimplemented")
}

// Public implements dsse.Verifier.
func (c *compositeVerifier) Public() crypto.PublicKey {
	return nil
}

// Verify implements dsse.Verifier.
func (c *compositeVerifier) Verify(ctx context.Context, data []byte, sig []byte) error {
	for _, v := range c.verifiers {
		if err := v.Verify(ctx, data, sig); err != nil {
			return err
		}
	}
	return nil
}
