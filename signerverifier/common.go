package signerverifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// must implement dsse.SignerVerifier interface.
var _ dsse.SignerVerifier = (*ECDSA256SignerVerifier)(nil)

type ECDSA256SignerVerifier struct {
	crypto.Signer
	dsse.Verifier
	keyID     string
	publicKey *ecdsa.PublicKey
}

func NewECDSA256SignerVerifier(signer crypto.Signer, verifier dsse.Verifier) dsse.SignerVerifier {
	return &ECDSA256SignerVerifier{
		Signer:   signer,
		Verifier: verifier,
	}
}

// implement keyid function.
func (s *ECDSA256SignerVerifier) KeyID() (string, error) {
	if s.keyID != "" {
		return s.keyID, nil
	}
	keyID, err := KeyID(s.Public())
	if err != nil {
		return "", err
	}
	s.keyID = keyID
	return keyID, nil
}

func (s *ECDSA256SignerVerifier) Public() crypto.PublicKey {
	if s.publicKey != nil {
		return s.publicKey
	}
	pub, ok := s.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	s.publicKey = pub
	return s.publicKey
}

func (s *ECDSA256SignerVerifier) Sign(_ context.Context, data []byte) ([]byte, error) {
	return s.Signer.Sign(rand.Reader, data, crypto.SHA256)
}

func (s *ECDSA256SignerVerifier) Verify(_ context.Context, data []byte, sig []byte) error {
	if s.Verifier == nil {
		return fmt.Errorf("no verifier found")
	}
	return s.Verifier.Verify(context.Background(), data, sig)
}

func LoadKeyPair(priv []byte) (dsse.SignerVerifier, error) {
	privateKey, err := parsePriv(priv)
	if err != nil {
		return nil, err
	}
	return &ECDSA256SignerVerifier{
		Signer: privateKey,
	}, nil
}

func parsePriv(privkeyBytes []byte) (*ecdsa.PrivateKey, error) {
	p, _ := pem.Decode(privkeyBytes)
	if p == nil {
		return nil, fmt.Errorf("privkey file does not contain any PEM data")
	}
	if p.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("privkey file does not contain a priavte key")
	}
	privKey, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error failed to parse public key: %w", err)
	}

	return privKey, nil
}

func GenKeyPair() (dsse.SignerVerifier, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDSA256SignerVerifier{
		Signer: signer,
	}, nil
}
