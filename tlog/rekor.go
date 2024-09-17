package tlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/attest/internal/util"
	"github.com/docker/attest/signerverifier"
	"github.com/docker/attest/tuf"
	"github.com/docker/attest/useragent"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	rclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"

	stuf "github.com/sigstore/sigstore/pkg/tuf"

	_ "embed"
)

const RekorTLExtKind = "Rekor"

// ensure it has all the necessary methods.
var _ TransparencyLog = (*Rekor)(nil)

const defaultPublicKeysDir = "rekor"

type Rekor struct {
	publicKeys    *cosign.TrustedTransparencyLogPubKeys
	tufDownloader tuf.Downloader
	publicKeysDir string
}

//go:embed keys/c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d.pem
var rekorPublicKey []byte

func WithTUFDownloader(tufDownloader tuf.Downloader) func(*Rekor) {
	return func(r *Rekor) {
		r.tufDownloader = tufDownloader
	}
}

func WithTUFPublicKeysDir(dir string) func(*Rekor) {
	return func(r *Rekor) {
		r.publicKeysDir = dir
	}
}

func NewRekorLog(options ...func(*Rekor)) (*Rekor, error) {
	pk, err := signerverifier.ParsePublicKey(rekorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing rekor public key: %w", err)
	}
	kid, err := signerverifier.KeyID(pk)
	if err != nil {
		return nil, fmt.Errorf("error getting keyid: %w", err)
	}
	keys := map[string]cosign.TransparencyLogPubKey{
		kid: {
			PubKey: pk,
			Status: stuf.Active,
		},
	}
	rekor := &Rekor{
		publicKeys: &cosign.TrustedTransparencyLogPubKeys{
			Keys: keys,
		},
		publicKeysDir: defaultPublicKeysDir,
	}
	for _, opt := range options {
		opt(rekor)
	}
	return rekor, nil
}

// UploadEntry submits a PK token signature to the transparency log.
func (tl *Rekor) UploadEntry(ctx context.Context, subject string, encPayload, signature []byte, signer dsse.SignerVerifier) (*DockerTLExtension, error) {
	// generate self-signed x509 cert
	pubCert, err := CreateX509Cert(subject, signer)
	if err != nil {
		return nil, fmt.Errorf("Error creating x509 cert: %w", err)
	}

	// generate hash of payload
	hasher := sha256.New()
	hasher.Write(encPayload)

	// upload entry
	rekorClient, err := rclient.GetRekorClient(DefaultRekorURL, rclient.WithUserAgent(useragent.Get(ctx)))
	if err != nil {
		return nil, fmt.Errorf("Error creating rekor client: %w", err)
	}
	entry, err := cosign.TLogUpload(ctx, rekorClient, signature, hasher, pubCert)
	if err != nil {
		return nil, fmt.Errorf("Error uploading tlog: %w", err)
	}

	return &DockerTLExtension{
		Kind: RekorTLExtKind,
		Data: entry, // transparency log entry metadata
	}, nil
}

// VerifyEntry verifies a transparency log entry.
func (tl *Rekor) VerifyEntry(ctx context.Context, ext *DockerTLExtension, encPayload, publicKey []byte) (time.Time, error) {
	zeroTime := time.Time{}
	// because the Data field has been unmarsalled into a map[string]interface{} we need to marshal it back to bytes
	// for the unmarshaler to work correctly
	entryBytes, err := json.Marshal(ext.Data)
	if err != nil {
		return time.Time{}, fmt.Errorf("error failed to marshal TL entry: %w", err)
	}

	entry, err := tl.UnmarshalEntry(entryBytes)
	if err != nil {
		return zeroTime, fmt.Errorf("error unmarshaling TL entry: %w", err)
	}

	err = entry.Validate(strfmt.Default)
	if err != nil {
		return zeroTime, fmt.Errorf("TL entry failed validation: %w", err)
	}
	// check if tl.publicKeys containers le.LogId
	_, ok := tl.publicKeys.Keys[*entry.LogID]
	if !ok {
		// otherwise check TUF
		pkTarget, err := tl.tufDownloader.DownloadTarget(filepath.Join(tl.publicKeysDir, fmt.Sprintf("%s.pem", *entry.LogID)), "")
		if err != nil {
			return zeroTime, fmt.Errorf("error downloading rekor public key %s: %w", *entry.LogID, err)
		}
		pk, err := signerverifier.ParsePublicKey(pkTarget.Data)
		if err != nil {
			return zeroTime, fmt.Errorf("error parsing public key: %w", err)
		}
		tl.publicKeys.Keys[*entry.LogID] = cosign.TransparencyLogPubKey{
			PubKey: pk,
			Status: stuf.Active,
		}
	}
	err = cosign.VerifyTLogEntryOffline(ctx, entry, tl.publicKeys)
	if err != nil {
		return zeroTime, fmt.Errorf("TL entry failed verification: %w", err)
	}

	integratedTime := time.Unix(*entry.IntegratedTime, 0)

	err = tl.VerifyEntryPayload(entry, encPayload, publicKey)
	if err != nil {
		return zeroTime, fmt.Errorf("error verifying TL entry payload: %w", err)
	}
	return integratedTime, nil
}

// VerifyEntryPayload checks that the TL entry payload matches envelope payload.
func (tl *Rekor) VerifyEntryPayload(entry *models.LogEntryAnon, payload, publicKey []byte) error {
	tlBody, ok := entry.Body.(string)
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

func (tl *Rekor) UnmarshalEntry(entry []byte) (*models.LogEntryAnon, error) {
	le := new(models.LogEntryAnon)
	err := le.UnmarshalBinary(entry)
	if err != nil {
		return nil, fmt.Errorf("error failed to unmarshal Rekor entry: %w", err)
	}
	return le, nil
}

func extractHashedRekord(body string) (*Payload, error) {
	sig := new(Payload)
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
