package cmd

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/attestation"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
	"github.com/docker/image-signer-verifier/pkg/signing"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const updateRequiredText = "image-signer-verifier is out of date. Please update to the latest version: https://github.com/docker/image-signer-verifier/releases/latest"

type verifierOptions struct {
	image     string
	platform  string
	policyDir string
	policyId  string
	*rootOptions
	vsa bool
	*signerOptions
	failOpen      bool
	lookupStyle   string
	referrersRepo string
	policyOptions *policy.PolicyOptions
}

func defaultVerifierOptions(opts *rootOptions) *verifierOptions {
	return &verifierOptions{
		rootOptions: opts,
		vsa:         false,
		failOpen:    false,
		lookupStyle: "referrers",
	}
}

func newVerifyCmd(opts *rootOptions) *cobra.Command {
	o := defaultVerifierOptions(opts)
	o.signerOptions = defaultSignerOptions(opts)
	cmd := &cobra.Command{
		Use:          "verify",
		Short:        "verify in-toto attestation signatures attached to Docker images using policy",
		SilenceUsage: true,
		RunE:         o.run,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateSignParameters(o.signerOptions)
		},
	}

	cmd.Flags().BoolVar(&o.vsa, "vsa", o.vsa, "Add a VSA to the image attestations")

	withSigningFlags(cmd, o.signerOptions)

	cmd.Flags().StringVarP(&o.platform, "platform", "p", "", "comma separated platforms to verify")
	cmd.Flags().StringVarP(&o.image, "image", "i", "", fmt.Sprintf("image in the form %s<image-name> or %s<local path>", oci.RegistryPrefix, oci.LocalPrefix))
	cmd.Flags().StringVarP(&o.policyDir, "policy-dir", "d", o.policyDir, "path to local policy directory")
	cmd.Flags().StringVar(&o.policyId, "policy-id", o.policyId, "Ignore mapping.yaml and use the policy with this ID")
	cmd.Flags().BoolVar(&o.failOpen, "fail-open", o.failOpen, "Set to true for policy to fail open if no policy for image found")
	cmd.Flags().StringVar(&o.lookupStyle, "lookup-style", o.lookupStyle, "Set to 'attached' to lookup attestations from image index, 'referrers' to lookup from via eferrers API")
	// adding for testing purposes so that we can use dynamic referrers repo
	cmd.Flags().StringVar(&o.referrersRepo, "referrers-source", o.referrersRepo, "Repo from which to fetch Referrers for attestation lookup")
	cmd.MarkFlagsRequiredTogether("vsa", "output")
	err := cmd.MarkFlagRequired("image")
	if err != nil {
		log.Fatalf("failed to mark flag required: %s", err)
	}
	return cmd
}

func (o *verifierOptions) run(cmd *cobra.Command, args []string) (err error) {
	if o.policyDir != "" && o.tufMockPath != "" {
		return fmt.Errorf("cannot use both policy-dir and tuf-mock-path")
	}
	ctx := cmd.Context()
	ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(o.debug))

	var tufClient tuf.TUFClient
	if o.tufMockPath != "" {
		tufClient = tuf.NewMockTufClient(o.tufMockPath, o.tufPath)
	} else {
		var tufRootBytes []byte
		if o.tufRootPath != "" {
			readBytes, err := os.ReadFile(o.tufRootPath)
			if err != nil {
				return fmt.Errorf("failed to read TUF root.json file: %w", err)
			}
			tufRootBytes = readBytes
		} else {
			tufRootBytes = o.tufRootBytes
		}

		tufClient, err = tuf.NewTufClient(tufRootBytes, o.tufPath, o.metadataURL, o.targetsURL, tuf.NewVersionChecker())
		if err != nil {
			invVerErr := new(tuf.InvalidVersionError)
			if errors.As(err, &invVerErr) {
				if o.debug {
					return fmt.Errorf("%s (%w)", updateRequiredText, invVerErr)
				}
				return fmt.Errorf(updateRequiredText)
			}
			return fmt.Errorf("failed to create TUF client: %w", err)
		}
	}

	policyStoreDir := filepath.Join(o.tufPath, "policy")
	sopts := &policy.PolicyOptions{
		TufClient:       tufClient,
		LocalTargetsDir: policyStoreDir,
		LocalPolicyDir:  o.policyDir,
		PolicyId:        o.policyId,
		ReferrersRepo:   o.referrersRepo,
	}
	o.policyOptions = sopts

	input, err := oci.ParseImageSpec(o.image)
	if err != nil {
		return err
	}
	inputs, err := input.ForPlatforms(o.platform)
	if err != nil {
		return err
	}
	for _, input := range inputs {
		result, err := evaluatePolicy(ctx, cmd, input, o)
		if err != nil {
			return err
		}

		if o.vsa {
			err = saveAttestations(ctx, input, result, o)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "VSA created\n")
		}
	}

	return nil
}

func saveAttestations(ctx context.Context, input *oci.ImageSpec, result *attest.VerificationResult, o *verifierOptions) error {
	// to ensure we are not resolving tag->digest again, which might give a different image
	var err error
	if input.Type != oci.OCI {
		input, err = oci.ParseImageSpec(fmt.Sprintf("%s@%s", input.Identifier, result.Input.Digest))
		if err != nil {
			return fmt.Errorf("failed to parse image source: %w", err)
		}
	}
	attIdx, err := oci.LoadSubjectIndex(input)
	if err != nil {
		return fmt.Errorf("failed to load attestation index: %w", err)
	}
	signer, err := GetSigner(ctx, o.signerOptions)
	if err != nil {
		return err
	}
	sopts := &attestation.SigningOptions{
		Replace:     !o.keep,
		SkipTL:      o.skipTL,
		SkipSubject: !o.Referrers,
	}
	outputs, err := oci.ParseImageSpecs(o.output)
	if err != nil {
		return err
	}
	if result.Outcome != attest.OutcomeSuccess {
		return nil
	}
	if o.Attach {
		images, err := attest.SignedAttestationImages(ctx, attIdx.Index, signer, sopts)
		if err != nil {
			return fmt.Errorf("failed to sign attestations on index: %w", err)
		}
		for _, image := range images {
			err = signing.SaveOutputImage(outputs, attIdx.Name, image)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		attIdx.Index, err = attest.AddAttestation(ctx, attIdx.Index, result.VSA, signer)
		if err != nil {
			return err
		}
		return signing.SaveOutputImage(outputs, attIdx.Name, attIdx.Index)
	}
}

func evaluatePolicy(ctx context.Context, cmd *cobra.Command, input *oci.ImageSpec, o *verifierOptions) (*attest.VerificationResult, error) {
	result, err := attest.Verify(ctx, input, o.policyOptions)
	if err != nil {
		return nil, err
	}
	err = processResult(cmd, input.Platform, result, o)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func processResult(cmd *cobra.Command, platform *v1.Platform, result *attest.VerificationResult, o *verifierOptions) error {
	prefix := fmt.Sprintf("Evaluation of policy for platform: '%s'...", platform.String())
	switch result.Outcome {
	case attest.OutcomeSuccess:
		fmt.Fprintln(cmd.OutOrStdout(), prefix+"OK")
	case attest.OutcomeNoPolicy:
		msg := prefix + "No policy found"
		if !o.failOpen || o.vsa {
			return fmt.Errorf(msg)
		}
		fmt.Fprintln(cmd.OutOrStdout(), msg)
	case attest.OutcomeFailure:
		for _, v := range result.Violations {
			y, err := yaml.Marshal(v)
			if err != nil {
				return fmt.Errorf("Failed to marshal violations: %w", err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "---\n%s", y)
		}
		return fmt.Errorf(prefix + "Failed")
	default:
		return fmt.Errorf("Unrecognized policy evaluation outcome: %s", result.Outcome)
	}
	return nil
}
