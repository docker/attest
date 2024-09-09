package tuf

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/docker/attest/version"
)

const ThisModulePath = "github.com/docker/attest"

type VersionChecker interface {
	// CheckVersion checks if the current version of this library meets the constraints from the TUF repo
	CheckVersion(tufClient Downloader) error
}

type InvalidVersionError struct {
	AttestVersion     string
	VersionConstraint string
	Errors            []error
}

func (e *InvalidVersionError) Error() string {
	var errsStr strings.Builder
	for i, err := range e.Errors {
		if i > 0 {
			errsStr.WriteString("; ")
		}
		errsStr.WriteString(err.Error())
	}
	return fmt.Sprintf("%s version %s does not satisfy constraints %s: %s", ThisModulePath, e.AttestVersion, e.VersionConstraint, errsStr.String())
}

func NewDefaultVersionChecker() *DefaultVersionChecker {
	return &DefaultVersionChecker{}
}

type DefaultVersionChecker struct{}

func (vc *DefaultVersionChecker) CheckVersion(client Downloader) error {
	attestVersion, err := version.Get()
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}
	if attestVersion == nil {
		return nil
	}
	// see https://github.com/Masterminds/semver/blob/v3.2.1/README.md#checking-version-constraints
	// for more information on the expected format of the version constraints in the TUF repo
	target, err := client.DownloadTarget("version-constraints", "")
	if err != nil {
		return fmt.Errorf("failed to download version-constraints: %w", err)
	}
	versionConstraints, err := semver.NewConstraint(string(target.Data))
	if err != nil {
		return fmt.Errorf("failed to parse minimum version: %w", err)
	}

	ok, errs := versionConstraints.Validate(attestVersion)
	if !ok {
		return &InvalidVersionError{
			AttestVersion:     attestVersion.String(),
			VersionConstraint: versionConstraints.String(),
			Errors:            errs,
		}
	}

	return nil
}
