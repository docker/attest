package attestation

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"github.com/docker/attest/signerverifier"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyDSSE(ctx context.Context, verifier Verifier, env *Envelope, opts *VerifyOptions) ([]byte, error) {
	// enforce payload type
	if !ValidPayloadType(env.PayloadType) {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found")
	}

	keys := make(map[string]*KeyMetadata, len(opts.Keys))
	for _, key := range opts.Keys {
		keys[key.ID] = key
	}

	payload, err := base64Encoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error failed to decode payload: %w", err)
	}

	encPayload := dsse.PAE(env.PayloadType, payload)
	// verify signatures and transparency log entry
	for _, sig := range env.Signatures {
		// resolve public key used to sign
		keyMeta, ok := keys[sig.KeyID]
		if !ok {
			return nil, fmt.Errorf("error key not found: %s", sig.KeyID)
		}

		if keyMeta.Distrust {
			return nil, fmt.Errorf("key %s is distrusted", keyMeta.ID)
		}
		publicKey, err := keyMeta.ParsedKey()
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		// decode signature
		signature, err := base64.StdEncoding.Strict().DecodeString(sig.Sig)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode signature: %w", err)
		}

		err = verifier.VerifySignature(ctx, publicKey, encPayload, signature, opts)
		if err != nil {
			return nil, fmt.Errorf("error failed to verify signature: %w", err)
		}
		if err := verifier.VerifyLog(ctx, keyMeta, encPayload, sig, opts); err != nil {
			return nil, fmt.Errorf("error failed to verify transparency log entry: %w", err)
		}
	}

	return payload, nil
}

func ValidPayloadType(payloadType string) bool {
	return payloadType == intoto.PayloadType || payloadType == ociv1.MediaTypeDescriptor
}

func (km *KeyMetadata) ParsedKey() (crypto.PublicKey, error) {
	if km.publicKey != nil {
		return km.publicKey, nil
	}
	publicKey, err := signerverifier.ParsePublicKey([]byte(km.PEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	km.publicKey = publicKey
	return publicKey, nil
}

func (km *KeyMetadata) UpdateImageExpirey(imageName string, platform *v1.Platform) error {
	// if there are NO custom expiries, assume key can be checked as normal
	if len(km.Expiries) == 0 {
		return nil
	}
	if km.From != nil || km.To != nil {
		return fmt.Errorf("error key has 'from' or 'to' time set which is not supported when `expiries` is set")
	}
	// update the key with the first matching expiry's times
	for _, expiry := range km.Expiries {
		if len(expiry.Patterns) == 0 {
			return fmt.Errorf("error need at least one expiry pattern")
		}
		for _, pattern := range expiry.Patterns {
			if pattern == "" {
				return fmt.Errorf("error empty expiry pattern")
			}
			patternRegex, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("error failed to compile expiry repo pattern: %w", err)
			}
			// if there's an image match, then platforms must match too
			if patternRegex.MatchString(imageName) {
				// either there are no platforms, or at least one must match
				if len(expiry.Platforms) == 0 {
					km.To = expiry.To
					km.From = expiry.From
					km.expired = false
					return nil
				}
				for _, expiryPlatform := range expiry.Platforms {
					parsedPlatform, err := v1.ParsePlatform(expiryPlatform)
					if err != nil {
						return fmt.Errorf("failed to parse platform %s: %w", expiryPlatform, err)
					}
					if parsedPlatform.Equals(*platform) {
						km.To = expiry.To
						km.From = expiry.From
						km.expired = false
						return nil
					}
				}
			}
		}
		// if we get here, and no expirey match the image, the key is expired
		km.expired = true
	}
	return nil
}

func (km *KeyMetadata) EnsureValid(t *time.Time) error {
	if km.expired {
		return fmt.Errorf("key %s was not valid at signing time %s", km.ID, t)
	}
	if km.To != nil && !t.Before(*km.To) {
		return fmt.Errorf("key %s was expired TL log time %s (key valid to %s)", km.ID, t, km.To)
	}
	if km.From != nil && t.Before(*km.From) {
		return fmt.Errorf("key %s was not yet valid at TL log time %s (key valid from %s)", km.ID, t, km.From)
	}
	return nil
}
