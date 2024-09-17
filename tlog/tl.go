package tlog

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/docker/attest/signerverifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	DefaultRekorURL = "https://rekor.sigstore.dev"
)

type TransparencyLog interface {
	UploadEntry(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) (*DockerTLExtension, error)
	VerifyEntry(ctx context.Context, entry *DockerTLExtension, payload, publicKey []byte) (time.Time, error)
}

type Payload struct {
	Algorithm string
	Hash      string
	Signature string
	PublicKey string
}

type DockerTLExtension struct {
	Kind string `json:"kind"`
	Data any    `json:"data"`
}

// CreateX509Cert generates a self-signed x509 cert for TL submission.
func CreateX509Cert(subject string, signer dsse.SignerVerifier) ([]byte, error) {
	// encode ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:            big.NewInt(1),
		Subject:                 pkix.Name{CommonName: subject},
		RawSubjectPublicKeyInfo: ecPub,
		NotBefore:               time.Now(),
		NotAfter:                time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid:   true,
		DNSNames:                []string{subject},
		IsCA:                    false,
	}

	// dsse.SignerVerifier doesn't implement cypto.Signer exactly

	csigner, err := signerverifier.AsCryptoSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("error converting signer to crypto.Signer: %w", err)
	}
	// create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), csigner)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}
