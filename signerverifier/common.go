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
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func LoadKeyPair(priv []byte) (dsse.SignerVerifier, error) {
	privateKey, err := parsePriv(priv)
	if err != nil {
		return nil, err
	}
	return NewECDSASignerVerifier(privateKey)
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
	return NewECDSASignerVerifier(signer)
}

// ensure it implements crypto.Signer.
var _ crypto.Signer = (*cryptoSignerWrapper)(nil)

type cryptoSignerWrapper struct {
	sv dsse.SignerVerifier
}

// Public implements crypto.Signer.
func (c *cryptoSignerWrapper) Public() crypto.PublicKey {
	return c.sv.Public()
}

// Sign implements crypto.Signer.
func (c *cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	return c.sv.Sign(context.Background(), digest)
}

func AsCryptoSigner(signer dsse.SignerVerifier) (crypto.Signer, error) {
	return &cryptoSignerWrapper{sv: signer}, nil
}
