package signerverifier

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const pemType = "PUBLIC KEY"

func ParsePublicKey(pubkeyBytes []byte) (*ecdsa.PublicKey, error) {
	p, _ := pem.Decode(pubkeyBytes)
	if p == nil {
		return nil, fmt.Errorf("pubkey file does not contain any PEM data")
	}
	if p.Type != pemType {
		return nil, fmt.Errorf("pubkey file does not contain a public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error failed to parse public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error public key is not an ecdsa key: %w", err)
	}
	return ecdsaPubKey, nil
}

func ConvertToPEM(ecdsaPubKey *ecdsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(ecdsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("error failed to marshal public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubKeyBytes}), nil
}
