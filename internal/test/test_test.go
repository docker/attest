package test

import (
	"path/filepath"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/assert"
)

var UnsignedTestImage = filepath.Join("..", "..", "test", "testdata", "unsigned-test-image")

const (
	ExpectedStatements = 4
)

func TestExtractAnnotatedStatements(t *testing.T) {
	statements, err := ExtractAnnotatedStatements(UnsignedTestImage, intoto.PayloadType)
	assert.NoError(t, err)
	assert.Equalf(t, len(statements), ExpectedStatements, "expected %d statement, got %d", ExpectedStatements, len(statements))
}
