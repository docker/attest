package signerverifier

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	awssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

// using AWS KMS.
func GetAWSSigner(ctx context.Context, keyARN string, region string) (dsse.SignerVerifier, error) {
	keyPath := fmt.Sprintf("awskms:///%s", keyARN)
	sv, err := awssigner.LoadSignerVerifier(ctx, keyPath, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("error loading aws signer verifier: %w", err)
	}
	cs, _, err := sv.CryptoSigner(context.Background(), func(_ error) {})
	if err != nil {
		return nil, fmt.Errorf("error getting aws crypto signer: %w", err)
	}
	return NewECDSASignerVerifier(cs)
}
