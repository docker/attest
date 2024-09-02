package attestation_test

import (
	"testing"

	"github.com/docker/attest/attestation"
	"github.com/docker/attest/internal/test"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
)

const ExpectedStatements = 4

func TestExtractAnnotatedStatements(t *testing.T) {
	statements, err := attestation.ExtractAnnotatedStatements(test.UnsignedTestImage(".."), intoto.PayloadType)
	assert.NoError(t, err)
	assert.Equalf(t, len(statements), ExpectedStatements, "expected %d statement, got %d", ExpectedStatements, len(statements))
}
