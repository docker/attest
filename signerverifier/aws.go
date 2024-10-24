/*
   Copyright Docker attest authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
