package signerverifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/docker/attest/internal/util"
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
	keyID, err := KeyID(v.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to get key ID: %w", err)
	}
	v.keyID = keyID
	return v.keyID, nil
}

// must implement dsse.SignerVerifier interface.
var _ dsse.SignerVerifier = (*ecdsa256SignerVerifier)(nil)

type ecdsa256SignerVerifier struct {
	signer crypto.Signer
	dsse.Verifier
}

func NewECDSASignerVerifier(signer crypto.Signer) (dsse.SignerVerifier, error) {
	verifier, err := NewECDSAVerifier(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}
	sv := &ecdsa256SignerVerifier{
		signer:   signer,
		Verifier: verifier,
	}
	return sv, nil
}

func (s *ecdsa256SignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return s.signer.Sign(rand.Reader, data, crypto.SHA256)
}
