package attestation

import (
	"context"
	"crypto"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"

	"github.com/distribution/reference"
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

	payload, err := base64Encoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error failed to decode payload: %w", err)
	}

	encPayload := dsse.PAE(env.PayloadType, payload)
	// verify signatures and transparency log entry
	for _, sig := range env.Signatures {
		// resolve public key used to sign
		keyMeta := opts.FindKey(sig.KeyID)
		if keyMeta == nil {
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

func (km *KeyMetadata) EnsureValid(imageName string, platform *v1.Platform, t *time.Time) error {
	// time must always be in the to/from range (if set)
	if km.To != nil && !t.Before(*km.To) {
		return fmt.Errorf("key %s was expired TL log time %s (key valid to %s)", km.ID, t, km.To)
	}
	if km.From != nil && t.Before(*km.From) {
		return fmt.Errorf("key %s was not yet valid at TL log time %s (key valid from %s)", km.ID, t, km.From)
	}

	if len(km.ValidityRanges) == 0 {
		return nil
	}
	parsed, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return fmt.Errorf("failed to parse image name: %w", err)
	}
	imageName = parsed.Name()
	// check that each range lies within the key's validity at the top level
	for _, validity := range km.ValidityRanges {
		if validity.To != nil && km.To != nil && !validity.To.Before(*km.To) {
			return fmt.Errorf("malformed validity range: %s is not before %s's valid 'to' date %s", validity.To, km.ID, km.To)
		}
		if validity.From != nil && km.From != nil && validity.From.Before(*km.From) {
			return fmt.Errorf("malformed validity range: %s is before %s's valid 'from' date %s", validity.From, km.ID, km.From)
		}
	}

	// find all validity ranges that match the image name and platform
	patternMatches := []*ValidityRange{}
	for _, validity := range km.ValidityRanges {
		if len(validity.Patterns) == 0 {
			return fmt.Errorf("error need at least one validity range pattern")
		}
		for _, pattern := range validity.Patterns {
			if pattern == "" {
				return fmt.Errorf("error empty validity pattern")
			}
			patternRegex, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("error failed to compile validity repo pattern: %w", err)
			}
			// if there's an image match, then platforms must match too
			if patternRegex.MatchString(imageName) {
				// either there are no platforms, or at least one must match
				if len(validity.Platforms) == 0 {
					patternMatches = append(patternMatches, validity)
				}
				for _, validityPlatform := range validity.Platforms {
					parsedPlatform, err := v1.ParsePlatform(validityPlatform)
					if err != nil {
						return fmt.Errorf("failed to parse platform %s: %w", validityPlatform, err)
					}
					if parsedPlatform.Equals(*platform) {
						patternMatches = append(patternMatches, validity)
					}
				}
			}
		}
	}
	if len(patternMatches) == 0 {
		return fmt.Errorf("no matching validity range found for key %s", km.ID)
	}
	if len(patternMatches) > 1 {
		return fmt.Errorf("key %s invalid, multiple matching validity ranges found", km.ID)
	}

	// now verify the time is within the validity range
	match := patternMatches[0]
	if match.To != nil && !t.Before(*match.To) {
		return fmt.Errorf("key %s was expired at TL log time %s (valid to %s)", km.ID, t, match.To)
	}
	if match.From != nil && t.Before(*match.From) {
		return fmt.Errorf("key %s was not yet valid at TL log time %s (valid from %s)", km.ID, t, match.From)
	}
	return nil
}

func (v *VerifyOptions) EnsureValid(ctx context.Context, km *KeyMetadata, t *time.Time) error {
	if v.Resolver == nil {
		return fmt.Errorf("error missing resolver")
	}
	imageName, err := v.Resolver.ImageName(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve image name: %w", err)
	}
	platform, err := v.Resolver.ImagePlatform(ctx)
	if err != nil {
		return fmt.Errorf("failed to get image platform: %w", err)
	}
	err = km.EnsureValid(imageName, platform, t)
	if err != nil {
		return err
	}
	return nil
}

func NewVerifyOptions(resolver Resolver) *VerifyOptions {
	v := &VerifyOptions{
		Resolver: resolver,
	}
	return v
}

func (v *VerifyOptions) FindKey(id string) *KeyMetadata {
	for _, key := range v.Keys {
		if key.ID == id {
			return key
		}
	}
	return nil
}
