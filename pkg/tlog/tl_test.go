package tlog

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/pkg/signerverifier"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

const (
	// test artifacts.
	TestPayload   = "test"
	TestPublicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAED4V+REhx+aqWH7ylMMDHahNMnMLS\nOJP/9kAm9lp+3mqYTAhURra6OD5Qx8Zbd+euPyPk9y+w/gWGDB9zn/Il1A==\n-----END PUBLIC KEY-----"
)

func TestCreateX509Cert(t *testing.T) {
	// TODO - replace with mock KMS
	// generate test signing keys
	signer, err := signerverifier.GenKeyPair()
	assert.NoError(t, err)

	// create x509 cert
	cert, err := CreateX509Cert("test", signer)
	assert.NoError(t, err)
	p, _ := pem.Decode(cert)
	result, err := x509.ParseCertificate(p.Bytes)
	assert.NoError(t, err)

	// test cert RawSubjectPublicKeyInfo field contains ephemeral public key
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	assert.NoError(t, err)
	assert.Equalf(t, string(result.RawSubjectPublicKeyInfo), string(ecPub), "certificate raw subject public key info does not match ephemeral public key")

	// test cert common name == subject
	assert.Equalf(t, result.Subject.CommonName, "test", "cert common name does not equal subject id")
}

func TestUploadAndVerifyLogEntry(t *testing.T) {
	// message digest
	payload := []byte("test")
	hash := util.SHA256(payload)

	// generate ephemeral keys to sign message digest
	signer, err := signerverifier.GenKeyPair()
	assert.NoError(t, err)
	sig, err := signer.Sign(context.Background(), hash)
	assert.NoError(t, err)

	var tl TL
	if UseMockTL {
		tl = &MockTL{
			UploadLogEntryFunc: func(_ context.Context, _ string, _ []byte, _ []byte, _ dsse.SignerVerifier) ([]byte, error) {
				return []byte(TestEntry), nil
			},
			VerifyLogEntryFunc: func(_ context.Context, _ []byte) (time.Time, error) {
				return time.Time{}, nil
			},
			VerifyEntryPayloadFunc: func(_, _, _ []byte) error {
				return nil
			},
		}
	} else {
		tl = &RekorTL{}
	}

	// test upload log entry
	ctx := WithTL(context.Background(), tl)
	entry, err := tl.UploadLogEntry(ctx, "test", payload, sig, signer)
	assert.NoError(t, err)

	// test verify log entry
	_, err = tl.VerifyLogEntry(ctx, entry)
	assert.NoError(t, err)

	// verify TL entry payload
	ecPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	assert.NoError(t, err)
	err = tl.VerifyEntryPayload(entry, payload, ecPub)
	assert.NoError(t, err)
}

func TestVerifyEntryPayload(t *testing.T) {
	tl := &RekorTL{}
	p, _ := pem.Decode([]byte(TestPublicKey))
	err := tl.VerifyEntryPayload([]byte(TestEntry), []byte(TestPayload), p.Bytes)
	assert.NoError(t, err)
}
