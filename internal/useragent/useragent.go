package useragent

import (
	"context"

	"github.com/docker/attest/internal/version"
)

type userAgentKeyType string

const (
	userAgentKey     userAgentKeyType = "attest-user-agent"
	defaultUserAgent string           = "attest/unknown (docker)"
)

func Set(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentKey, userAgent)
}

// Get retrieves the HTTP user agent from the context.
func Get(ctx context.Context) string {
	if ua, ok := ctx.Value(userAgentKey).(string); ok {
		return ua
	}
	version, err := version.Get()
	if err != nil || version == nil {
		return defaultUserAgent
	}

	return "attest/" + version.String() + " (docker)"
}
