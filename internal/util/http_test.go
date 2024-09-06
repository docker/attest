package util

import (
	"context"
	"testing"
)

// test the user agent setting and getting.
func TestSetUserAgent(t *testing.T) {
	ctx := context.Background()
	if GetUserAgent(ctx) != defaultUserAgent {
		t.Errorf("expected user agent to be '%s', got %q", defaultUserAgent, GetUserAgent(ctx))
	}

	ctx = SetUserAgent(ctx, "test-agent")
	if GetUserAgent(ctx) != "test-agent" {
		t.Errorf("expected user agent to be 'test-agent', got %q", GetUserAgent(ctx))
	}
}
