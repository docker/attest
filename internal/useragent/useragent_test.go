package useragent

import (
	"context"
	"testing"
)

// test the user agent setting and getting.
func TestSetUserAgent(t *testing.T) {
	ctx := context.Background()
	if Get(ctx) != defaultUserAgent {
		t.Errorf("expected user agent to be '%s', got %q", defaultUserAgent, Get(ctx))
	}

	ctx = Set(ctx, "test-agent")
	if Get(ctx) != "test-agent" {
		t.Errorf("expected user agent to be 'test-agent', got %q", Get(ctx))
	}
}
