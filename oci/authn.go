package oci

import (
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func MultiKeychainOption() remote.Option {
	return remote.WithAuthFromKeychain(MultiKeychainAll())
}

func MultiKeychainAll() authn.Keychain {
	// Create a multi-keychain that will use the default Docker, Google, or ECR keychain
	return authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper()),
	)
}
