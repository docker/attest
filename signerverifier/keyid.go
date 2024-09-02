package signerverifier

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/docker/attest/internal/util"
)

func KeyID(pubKey crypto.PublicKey) (string, error) {
	pub, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("error marshaling public key: %w", err)
	}
	return util.SHA256Hex(pub), nil
}
