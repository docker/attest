# `attest`

<div align="center">
Library to create attestation signatures on container images, and verify images against policy.

[![Go Reference](https://pkg.go.dev/badge/github.com/docker/attest.svg)](https://pkg.go.dev/github.com/docker/attest)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/docker/attest/test.yml?branch=main)](https://github.com/docker/attest/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/docker/attest/graph/badge.svg?token=cGT0f1ACKg)](https://codecov.io/gh/docker/attest)

</div>

# Table of Contents

- [`attest`](#attest)
- [Table of Contents](#table-of-contents)
- [What is this?](#what-is-this)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Verifying Image Attestations](#verifying-image-attestations)
  - [Signing Attestations](#signing-attestations)
- [Rego Policy](#rego-policy)
  - [Writing Policy](#writing-policy)
    - [Input](#input)
    - [Builtin Functions](#builtin-functions)
  - [Policy Mapping](#policy-mapping)
- [Public Key IDs](#public-key-ids)
- [Transparency Logging](#transparency-logging)
- [Verification Summary Attestation (VSA)](#verification-summary-attestation-vsa)
  - [Example VSA](#example-vsa)
- [API Reference](#api-reference)
- [Project Layout](#project-layout)
- [Versioning](#versioning)

# What is this?

`attest` is a library for signing and verifying [in-toto](https://in-toto.io/) attestations on container images.
Examples of attestations include statements about the provenance and SBOM of an image.

This library can be used to verify these attestations using Rego policy.
Policy can be used to check whether an attestation is correctly signed, and that the contents of the attestation are correct.

Our overall goal with this project is adoption of the ideas into other open-source projects, rather than to create another standalone tool.
It would be a great outcome if this library was no longer needed because the functionality was built into other tools.

# Features

- Sign in-toto attestations
- Push attestations to container registries using OCI 1.1 compatible artifacts
- Verify attestations on container images using Rego policy and attestations fetched using OCI 1.1 referrers

# Installation

```shell
$ go get github.com/docker/attest
```

# Usage

## Verifying Image Attestations

An image's attestations can be verified against a policy using the `attest.Verify` function.
This function takes an [oci.ImageSpec](https://github.com/docker/attest/blob/781a738b54b9549c1dabfd7ea3f7ea582514ddec/pkg/oci/types.go#L35-L41) for the image to verify, and a set of options for policy resolution.
By default, the policy is resolved from the [the Docker TUF repository](https://github.com/docker/tuf), but the options can be used to specify an alternative TUF repository, a local policy directory, and/or a policy ID to use.
See [Policy Mapping](#policy-mapping) for more details.

The `attest.Verify` function returns a `VerificationSummary` object, which contains the results of the policy evaluation.

See [example_verify_test.go](./example_verify_test.go) for an example of how to verify an image against a policy.

## Signing Attestations

in-toto statements can be signed directly using the `attestation.SignInTotoStatement` function.
This function takes a statement and DSSE signer, and returns a signed DSSE envelope containing a copy of the original statement.

For the common use case of signing a statement and adding it to a manifest, e.g. for pushing to a registry as a referrer to the image being attested, the `attestation.AttestationManifest` type can be used.
See [example_attestation_manifest_test.go](./pkg/attestation/example_attestation_manifest_test.go)

See also [example_sign_test.go](./example_sign_test.go) for an example of how to sign all attached in-toto statements on an image, e.g. those produced by buildkit.

# Rego Policy

An image policy consists of one or more `rego` files and, optionally, `json` or `yaml` data files.

The policies for trusted namespaces `docker.io/docker` and `docker.io/library` are stored in [the Docker TUF root](https://github.com/docker/tuf) under the `docker` and `doi` target sub-directories respectively.

## Writing Policy

`attest` uses [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) for policy evaluation, and policies are written in Rego.
A full guide to writing Rego policies is available in the [Rego documentation](https://www.openpolicyagent.org/docs/latest/policy-language/).

For attest, a policy must contain at a minimum a `result` rule in a package called `attest` that returns an object matching the schema defined by the [`policy.Result`](https://github.com/docker/attest/blob/bd2c4d7d8aa497754b674412b09628be8d02fab5/pkg/policy/types.go#L23-L27) struct.
For example:

```rego
package attest

import rego.v1

result := {
	"success": true,
	"violations": set(),
	"summary": {
		"subjects": subjects,
		"slsa_levels": ["SLSA_BUILD_LEVEL_3"],
		"verifier": "docker-official-images",
		"policy_uri": "https://docker.com/official/policy/v0.1",
	},
}
```

The meanings of the fields in the `result` object are as follows:

- `success` (bool): whether the policy passes
- `violations` (set): a set of strings describing any policy violations
- `summary` (object): a summary of the policy evaluation, used to construct a Verification Summary Attestation (VSA)
  - `subjects` (set): a set of strings representing the subjects of each attestation that was evaluated
  - `slsa_levels` (list): a list of strings representing the SLSA levels that the policy complies with
  - `verifier` (string): the entity that verified the policy
  - `policy_uri` (string): the URI of the policy

The `violations` set may contain policy violations even if `success` is `true`.
This can be useful if there are attestations that are invalid, but are not required by the policy.

### Input

The input to the policy is an object with the following fields:

- `digest` (string): the digest of the image being verified
- `purl` (string): the package URL of the image being verified
- `platform` (string): the platform of the image being verified
- `normalized_name` (string): defaults are filled out. e.g. if the image is `alpine`, this would be `library/alpine`
- `familiar_name` (string): short version of above (e.g. `alpine`)
- `tag`: (string): tag of the image being verified (if present)

### Builtin Functions

There are two builtin functions provided by `attest` that can be used to help with policy evaluation:

- `attest.fetch(predicate_type)`: fetches all attestations for the input image with the given predicate type.
  For example, `attest.fetch("https://spdx.dev/Document")` will fetch all SPDX SBOM attestations for the input image.
- `attest.verify(attestation, options)`: verifies the DSSE envelope of the given attestation, and returns the statement.
  The options object can contain the following fields:
  - `keys` (array): keys to use for signature verification. Each key contains the following fields:
    - `id` (string): the key ID as specified in [Public Key IDs](#public-key-ids)
    - `key` (string): the PEM-encoded public key
    - `from` (string): the time from which the key is valid, or `null` if the key was always valid (default: `null`)
    - `status` (string): `active` if the key is active, otherwise the reason the key is inactive.
      This is only used in error messages if the `from` date is in the past
    - `distrust` (bool): whether the key should be distrusted (default: `false`).
      If `true`, the key will be considered invalid
    - `signing-format` (string): the format of the signing key, must be `dssev1`
  - `skip_tl` (bool): whether to skip transparency log entry verification (see [Transparency Logging](#transparency-logging)) (default: `false`)

Both `attest.fetch` and `attest.verify` return an object with the following fields:

- `value`: the return value of the function if successful
- `error`: an error message if the function failed

This is to allow the policy to easily construct a violation if an error occurs, which isn't usually possible with custom functions in Rego.

The return value of `attest.fetch` is an attestation which can be passed to `attest.verify`.

## Policy Mapping

A `mapping.yaml` file is stored at the root of TUF targets and contains the mapping from repository name to files containing the corresponding policy.

A simple mapping file might look like this:

```yaml
version: v1
kind: policy-mapping
policies:
  - id: docker-official-images
    description: Docker Official Images
    files:
      - path: doi/policy.rego
rules:
  - pattern: "^docker[.]io/library/(.*)$"
    policy-id: docker-official-images
```

The `policies` section contains a list of policies, each with an `id` and a `description`, and a list of `files` containing the policy.
The `rules` section contains a list of rules that map regex expressions to policies.
If the `pattern` regex matches the repository name, the policy with the `policy-id` is used to evaluate the image.
In the above example, any repository in the `docker.io/library` namespace will be evaluated against the policy in `doi/policy.rego`.

Sometimes it is necessary to rewrite the repository name before evaluating the policy.
This can be useful when the repository name which is used to reference the image is different from the repository name in the attestations.
For example, when mirroring images from a public registry to a private registry, the repository name in the attestations will be the public registry, but the image will be referenced by the name of the private registry.

An example of a mapping file with rewrite rules might look like this:

```yaml
version: v1
kind: policy-mapping
policies:
  - id: docker-official-images
    description: Docker Official Images
    files:
      - path: doi/policy.rego
rules:
  - pattern: "^docker[.]io/library/(.*)$"
    policy-id: docker-official-images
  - pattern: "^public[.]ecr[.]aws/docker/library/(.*)$"
    platforms: ["linux/amd64"] # optional to restrict to specific platforms for this rule (empty matches all)
    rewrite: docker.io/library/$1
```

As before, any repository in the `docker.io/library` namespace will be evaluated against the policy in `doi/policy.rego`.
The second rule will rewrite any repository in the `public.ecr.aws/docker/library` namespace to `docker.io/library`.
This means two things:

1. The rules are evaluated again using the rewritten repository name until a policy is found (in this case the first rule will match); and
2. The rewritten name is passed into the actual policy when it is evaluated.

The `rewrite` field is not a simple string replacement, but a regex replacement.
This means that the `rewrite` field can contain capture groups that are referenced in the `pattern` field.
For example, the `rewrite` field in the example above contains `$1`, which is a reference to the first capture group in the `pattern` field.

> [!IMPORTANT]
> It's important to remember to escape the `.` character in the `pattern` field, as it is a special character in regex.
> This is why the `.` character is surrounded by `[]` in the example above.
>
> It's also important to make use of the `^` and `$` characters in the `pattern` field to ensure that the regex matches the entire repository name.
> This is to prevent the regex from matching a subset of the repository name, e.g. `docker.io/library` matching `notdocker.io/library`.

Local policy can also be specified via a local `mapping.yaml`, which can be used to create new mirrors of policies described in the Docker TUF root, as well as describing entirely independent policies. For example:

```golang
// configure policy options
opts := &policy.PolicyOptions{
  TufClient:       tufClient,
  LocalPolicyDir:  "<policy-dir>", // overrides TUF policy for local policy files if set
  PolicyId:        "<policy-id>", // set to ignore policy mapping and select a policy by id
}

src, err := oci.ParseImageSpec(image, oci.WithPlatform(platform))
if err != nil {
  panic(err)
}
// verify attestations
result, err := attest.Verify(context.Background(), src, opts)
if err != nil {
  panic(err)
}
```

where `<policy-dir>` is a directory containing a `mapping.yaml` file, and any policy files referenced in the `mapping.yaml`. For example:

```
├── myimages
│   ├── data.yaml
|   ├── keys.yaml
│   └── policy.rego
└── mapping.yaml
```

> [!NOTE]
>
> `PolicyId` can also be set to select a policy by ID, completely ignoring the `rules` section of the mapping file.

The rules section of a local `mapping.yaml` can refer to the policies described in the `mapping.yaml` file in the Docker TUF root to specify additional mirrors to which the referenced policy can be applied.

For example, it might be desirable to mirror `docker.io/library` to a local registry for testing:

```yaml
version: v1
kind: policy-mapping
rules:
  - pattern: "^localhost:5001/(.*)$"
    rewrite: docker.io/library/$1
```

The rewritten repository name will match the `docker-official-images` polict in the TUF managed `mapping.yaml`.

> [!WARNING]
> Local `mapping.yaml` policies take precendence over TUF managed policies, so for example, it's possible to apply a custom policy to `docker.io/library` namespace:
>
> ```yaml
> version: v1
> kind: policy-mapping
> policies:
>   - id: mydoi
>     description: my doi policy
>     files:
>       - path: "mypolicy.rego"
>
> rules:
>   - pattern: "^docker[.]io/library/(.*)$"
>     policy-id: mydoi
> ```

# Public Key IDs

When signing attestations, a key-id is generated from the public key and added to envelope.
This is used at verification time to look up the public key.

To generate a key-id from a public key, use `openssl` as follows:

```shell
openssl pkey -in <public-key.pem> -pubin -outform DER | openssl dgst -sha256
```

# Transparency Logging

`attest` supports transparency logging for attestation signatures.
This serves two purposes:

1. the transparency log is a mechanism to ensure that all attestations are logged in a tamper-evident way, and that the logs are publicly auditable; and
2. the transparency log is a trusted source of timestamps for attestations, which allows signatures to be verified even if the key used to sign the attestation has expired.

By default, transparency logging is enabled and the logs are stored in the [public-good Rekor](https://docs.sigstore.dev/logging/overview/) instance.
Another transparency log can be used by creating an implementation of the [tl.TL](https://github.com/docker/attest/blob/781a738b54b9549c1dabfd7ea3f7ea582514ddec/pkg/tlog/tl.go#L57-L62) interface and using [`tl.WithTL`](https://github.com/docker/attest/blob/781a738b54b9549c1dabfd7ea3f7ea582514ddec/pkg/tlog/tl.go#L37) to set in on a context.
Alternatively, transparency logging can be disabled when signing by using `SkipTL` in the `SigningOptions`, and when verifying by using `skip_tl` in the options to `attest.verify` in the Rego policy.

# Verification Summary Attestation (VSA)

Verification of attestations can be expensive, especially when the attestations are large.
For example, an SBOM attestation can be several megabytes in size.
An alternative to consumers verifying the full attestation is to have a trusted entity verify the attestation and publish a [SLSA Verification Summary Attestation](https://slsa.dev/spec/v1.0/verification_summary) (VSA) to the registry.
The VSA can then be verified by the consumer without needing to verify the full attestation, as long as the consumer trusts the entity that signed the VSA.
This is useful when the consumer only needs to know that the attestation was verified by a trusted entity, and does not need to know the details of the attestation.

A useful pattern is to have apply a policy to a third-party image at initial ingress, then publish a VSA when publishing the image to an internal registry to attest that the image complies with the policy.
The VSA can be verified very quickly, for example in a Kubernetes admission controller.

`attest` always generates a [SLSA VSA](https://slsa.dev/spec/v1.0/verification_summary) when verifying attestations on an image.
The VSA can be signed and published to the registry using the signing functions mentioned in [Signing Attestations](#signing-attestations).

## Example VSA

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:docker/example.org/example-image@1.0?platform=linux%2Famd64",
      "digest": {
        "sha256": "49f717386e5462e945232569a97a05831cb83bef8c3369be3bb7ea1793686960"
      }
    }
  ],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": {
      "id": "https://example.org/internal-verifier"
    },
    "timeVerified": "2024-04-19T08:00:00.01Z",
    "resourceUri": "pkg:docker/example.org/example-image@1.0?platform=linux%2Famd64&digest=sha256%3A49f717386e5462e945232569a97a05831cb83bef8c3369be3bb7ea1793686960",
    "policy": {
      "uri": "https://example.org/internal-policy/v1",
      "downloadLocation": "https://docker.github.io/tuf-staging/targets/docker/d71d6b8f49fcba1295b16f5394dd5863a14e4277eb663d66d8c48e392509afe0.policy.rego",
      "digest": {
        "sha256": "d71d6b8f49fcba1295b16f5394dd5863a14e4277eb663d66d8c48e392509afe0"
      }
    },
    "verificationResult": "PASSED",
    "verifiedLevels": ["SLSA_BUILD_LEVEL_3"]
  }
}
```

# API Reference

Full API reference can be found at [pkg.go.dev/github.com/docker/attest](https://pkg.go.dev/github.com/docker/attest).

# Project Layout

- [pkg/](https://pkg.go.dev/github.com/docker/image-signer-verifier/pkg) => packages that are okay to import for other projects
- [internal/](https://pkg.go.dev/github.com/docker/image-signer-verifier/pkg) => packages that are only for project internal purposes
- [scripts/](scripts/) => build scripts
- [test/](test/) => data for use in tests

# Versioning

`attest` uses [Semantic Versioning](https://semver.org/).
As such, until `attest` reaches version 1.0.0, breaking changes may be introduced in minor versions.

> Anything MAY change at any time. The public API SHOULD NOT be considered stable.
