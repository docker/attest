package oci

import (
	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	acr "github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func MultiKeychainOption() remote.Option {
	return remote.WithAuthFromKeychain(MultiKeychainAll())
}

func MultiKeychainAll() authn.Keychain {
	// Create a multi-keychain that will use the default Docker, Google, ECR or ACR keychain
	return authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		authn.NewKeychainFromHelper(ecr.NewECRHelper()),
		authn.NewKeychainFromHelper(acr.NewACRCredentialsHelper()),
	)
}