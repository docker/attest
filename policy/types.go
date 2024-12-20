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

package policy

import (
	"github.com/docker/attest/attestation"
	"github.com/docker/attest/mapping"
	"github.com/docker/attest/tuf"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

type Summary struct {
	Subjects   []intoto.Subject                 `json:"subjects"`
	Inputs     []attestation.ResourceDescriptor `json:"input_attestations"`
	SLSALevels []string                         `json:"slsa_levels"`
	Verifier   string                           `json:"verifier"`
	PolicyURI  string                           `json:"policy_uri"`
}

type Violation struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Attestation *intoto.Statement `json:"attestation"`
	Details     map[string]any    `json:"details"`
}

type Result struct {
	Success    bool        `json:"success"`
	Violations []Violation `json:"violations"`
	Summary    Summary     `json:"summary"`
}

type Options struct {
	TUFClientOptions    *tuf.ClientOptions
	DisableTUF          bool
	LocalTargetsDir     string
	LocalPolicyDir      string
	PolicyID            string
	ReferrersRepo       string
	AttestationStyle    mapping.AttestationStyle
	Debug               bool
	AttestationVerifier attestation.Verifier
	// extra parameters to pass through to rego as policy inputs
	Parameters Parameters
}

type Parameters map[string]string

type Policy struct {
	InputFiles   []*File
	Query        string
	Mapping      *mapping.PolicyMapping
	ResolvedName string
	URI          string
	Digest       map[string]string
}

type Input struct {
	Digest         string     `json:"digest"`
	PURL           string     `json:"purl"`
	Tag            string     `json:"tag,omitempty"`
	Domain         string     `json:"domain"`
	NormalizedName string     `json:"normalized_name"`
	FamiliarName   string     `json:"familiar_name"`
	Platform       string     `json:"platform"`
	Parameters     Parameters `json:"parameters"`
}

type File struct {
	Path    string
	Content []byte
}
