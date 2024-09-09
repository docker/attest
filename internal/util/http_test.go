package util

import (
	"context"
	"testing"
	"useragent"
)

import (
	"context"
	"testing"
)

// test the user agent setting and getting.
func TestSetUserAgent(t *testing.T) {
	ctx := context.Background()
	if useragent.Get(ctx) != useragent.defaultUserAgent {
		t.Errorf("expected user agent to be '%s', got %q", useragent.defaultUserAgent, useragent.Get(ctx))
	}

	ctx = useragent.Set(ctx, "test-agent")
	if useragent.Get(ctx) != "test-agent" {
		t.Errorf("expected user agent to be 'test-agent', got %q", useragent.Get(ctx))
	}
}
