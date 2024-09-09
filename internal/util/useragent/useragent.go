package useragent

import "context"

type userAgentKeyType string

const (
	userAgentKey     userAgentKeyType = "attest-user-agent"
	defaultUserAgent string           = "attest/v0.4.4 (docker)"
)

func Set(ctx context.Context, userAgent string) context.Context {
	return context.WithValue(ctx, userAgentKey, userAgent)
}

// Get retrieves the HTTP user agent from the context.
func Get(ctx context.Context) string {
	if ua, ok := ctx.Value(userAgentKey).(string); ok {
		return ua
	}
	return defaultUserAgent
}
