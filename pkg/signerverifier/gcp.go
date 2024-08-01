package signerverifier

import (
	"context"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	gcpsigner "github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"google.golang.org/api/option"
)

// using GCP KMS
// reference should be in the format projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/cryptoKeyVersions/[VERSION].
func GetGCPSigner(ctx context.Context, reference string, opts ...option.ClientOption) (dsse.SignerVerifier, error) {
	reference = fmt.Sprintf("gcpkms://%s", reference)
	sv, err := gcpsigner.LoadSignerVerifier(ctx, reference, opts...)
	if err != nil {
		return nil, fmt.Errorf("error loading gcp signer verifier: %w", err)
	}
	cs, _, err := sv.CryptoSigner(ctx, func(_ error) {})
	if err != nil {
		return nil, fmt.Errorf("error getting gcp crypto signer: %w", err)
	}
	signer := &ECDSA256SignerVerifier{
		Signer: cs,
	}
	return signer, nil
}
