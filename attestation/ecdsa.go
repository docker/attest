package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"fmt"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type ecdsaVerifier struct {
	publicKey *ecdsa.PublicKey
	keyID     string
}

// ensure ECDSAVerifier implements dsse.Verifier.
var _ dsse.Verifier = (*ecdsaVerifier)(nil)

func NewECDSAVerifier(publicKey crypto.PublicKey) (dsse.Verifier, error) {
	ecdsaPublicKey, ok := (publicKey).(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ECDSA public key")
	}
	return &ecdsaVerifier{
		publicKey: ecdsaPublicKey,
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
	if v.keyID != "" {
		return v.keyID, nil
	}
	keyID, err := signerverifier.KeyID(v.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to get key ID: %w", err)
	}
	v.keyID = keyID
	return v.keyID, nil
}
