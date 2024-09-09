package tlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/useragent"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	rclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

const (
	DefaultRekorURL = "https://rekor.sigstore.dev"
)

type tlCtxKeyType struct{}

var TLCtxKey tlCtxKeyType

// sets TL in context.
func WithTL(ctx context.Context, tl TL) context.Context {
	return context.WithValue(ctx, TLCtxKey, tl)
}

// gets TL from context, defaults to Rekor TL if not set.
func GetTL(ctx context.Context) TL {
	t, ok := ctx.Value(TLCtxKey).(TL)
	if !ok {
		t = &RekorTL{}
	}
	return t
}

type TLPayload struct {
	Algorithm string
	Hash      string
	Signature string
	PublicKey string
}

type TL interface {
	UploadLogEntry(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) ([]byte, error)
	VerifyLogEntry(ctx context.Context, entryBytes []byte) (time.Time, error)
	VerifyEntryPayload(entryBytes, payload, publicKey []byte) error
	UnmarshalEntry(entryBytes []byte) (any, error)
}

type MockTL struct {
	UploadLogEntryFunc     func(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) ([]byte, error)
	VerifyLogEntryFunc     func(ctx context.Context, entryBytes []byte) (time.Time, error)
	VerifyEntryPayloadFunc func(entryBytes, payload, publicKey []byte) error
	UnmarshalEntryFunc     func(entryBytes []byte) (any, error)
}

func (tl *MockTL) UploadLogEntry(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) ([]byte, error) {
	if tl.UploadLogEntryFunc != nil {
		return tl.UploadLogEntryFunc(ctx, subject, payload, signature, signer)
	}
	return nil, nil
}

func (tl *MockTL) VerifyLogEntry(ctx context.Context, entryBytes []byte) (time.Time, error) {
	if tl.VerifyLogEntryFunc != nil {
		return tl.VerifyLogEntryFunc(ctx, entryBytes)
	}
	return time.Time{}, nil
}

func (tl *MockTL) VerifyEntryPayload(entryBytes, payload, publicKey []byte) error {
	if tl.VerifyEntryPayloadFunc != nil {
		return tl.VerifyEntryPayloadFunc(entryBytes, payload, publicKey)
	}
	return nil
}

func (tl *MockTL) UnmarshalEntry(entryBytes []byte) (any, error) {
	if tl.UnmarshalEntryFunc != nil {
		return tl.UnmarshalEntryFunc(entryBytes)
	}
	return nil, nil
}

type RekorTL struct{}

// UploadLogEntry submits a PK token signature to the transparency log.
func (tl *RekorTL) UploadLogEntry(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) ([]byte, error) {
	// generate self-signed x509 cert
	pubCert, err := CreateX509Cert(subject, signer)
	if err != nil {
		return nil, fmt.Errorf("Error creating x509 cert: %w", err)
	}

	// generate hash of payload
	hasher := sha256.New()
	hasher.Write(payload)

	// upload entry
	rekorClient, err := rclient.GetRekorClient(DefaultRekorURL, rclient.WithUserAgent(useragent.Get(ctx)))
	if err != nil {
		return nil, fmt.Errorf("Error creating rekor client: %w", err)
	}
	entry, err := cosign.TLogUpload(ctx, rekorClient, signature, hasher, pubCert)
	if err != nil {
		return nil, fmt.Errorf("Error uploading tlog: %w", err)
	}
	entryBytes, err := entry.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("error marshaling TL entry: %w", err)
	}
	return entryBytes, nil
}

// VerifyLogEntry verifies a transparency log entry.
func (tl *RekorTL) VerifyLogEntry(ctx context.Context, entryBytes []byte) (time.Time, error) {
	zeroTime := time.Time{}
	entry, err := tl.UnmarshalEntry(entryBytes)
	if err != nil {
		return zeroTime, fmt.Errorf("error failed to unmarshal TL entry: %w", err)
	}
	le, ok := entry.(*models.LogEntryAnon)
	if !ok {
		return zeroTime, fmt.Errorf("expected entry to be of type *models.LogEntryAnon, got %T", entry)
	}
	err = le.Validate(strfmt.Default)
	if err != nil {
		return zeroTime, fmt.Errorf("TL entry failed validation: %w", err)
	}

	// TODO: get rekor public keys from TUF (ours or theirs?), and/or embed the public key in the binary
	rekorPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return zeroTime, fmt.Errorf("error failed to get rekor public keys: %w", err)
	}
	err = cosign.VerifyTLogEntryOffline(ctx, le, rekorPubKeys)
	if err != nil {
		return zeroTime, fmt.Errorf("TL entry failed verification: %w", err)
	}

	integratedTime := time.Unix(*le.IntegratedTime, 0)

	return integratedTime, nil
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

	csigner, ok := signer.(*signerverifier.ECDSA256SignerVerifier)
	if !ok {
		return nil, fmt.Errorf("expected signer to be of type *signerverifier.ECDSA_SignerVerifier, got %T", signer)
	}
	// create a self-signed X.509 certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, signer.Public(), csigner.Signer)
	if err != nil {
		return nil, fmt.Errorf("error creating X.509 certificate: %w", err)
	}
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	return pem.EncodeToMemory(certBlock), nil
}

// VerifyEntryPayload checks that the TL entry payload matches envelope payload.
func (tl *RekorTL) VerifyEntryPayload(entryBytes, payload, publicKey []byte) error {
	entry, err := tl.UnmarshalEntry(entryBytes)
	if err != nil {
		return fmt.Errorf("error failed to unmarshal TL entry: %w", err)
	}
	le, ok := entry.(*models.LogEntryAnon)
	if !ok {
		return fmt.Errorf("expected tl entry to be of type *models.LogEntryAnon, got %T", entry)
	}
	tlBody, ok := le.Body.(string)
	if !ok {
		return fmt.Errorf("expected tl body to be of type string, got %T", entry)
	}
	rekord, err := extractHashedRekord(tlBody)
	if err != nil {
		return fmt.Errorf("error extract HashedRekord from TL entry: %w", err)
	}

	// compare payload hashes
	payloadHash := util.SHA256Hex(payload)
	if rekord.Hash != payloadHash {
		return fmt.Errorf("error payload and tl entry hash mismatch")
	}

	// compare public keys
	cert, err := base64.StdEncoding.Strict().DecodeString(rekord.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	p, _ := pem.Decode(cert)
	result, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	if !bytes.Equal(result.RawSubjectPublicKeyInfo, publicKey) {
		return fmt.Errorf("error payload and tl entry public key mismatch")
	}
	return nil
}

func (tl *RekorTL) UnmarshalEntry(entry []byte) (any, error) {
	le := new(models.LogEntryAnon)
	err := le.UnmarshalBinary(entry)
	if err != nil {
		return nil, fmt.Errorf("error failed to unmarshal TL entry: %w", err)
	}
	return le, nil
}

func extractHashedRekord(body string) (*TLPayload, error) {
	sig := new(TLPayload)
	pe, err := models.UnmarshalProposedEntry(base64.NewDecoder(base64.StdEncoding, strings.NewReader(body)), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	impl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}
	switch entry := impl.(type) {
	case *hashedrekord_v001.V001Entry:
		sig.Algorithm = *entry.HashedRekordObj.Data.Hash.Algorithm
		sig.Hash = *entry.HashedRekordObj.Data.Hash.Value
		sig.Signature = entry.HashedRekordObj.Signature.Content.String()
		sig.PublicKey = entry.HashedRekordObj.Signature.PublicKey.Content.String()
		return sig, nil
	default:
		return nil, fmt.Errorf("failed to extract haskedrekord, unsupported type: %T", entry)
	}
}
