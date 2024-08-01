package oci

import (
	"net/http"

	"github.com/hashicorp/go-cleanhttp"
)

type userAgentTransporter struct {
	userAgent    string
	routeTripper http.RoundTripper
}

type Option = func(*http.Client)

func (u *userAgentTransporter) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", u.userAgent)

	return u.routeTripper.RoundTrip(req)
}

func HTTPTransport() http.RoundTripper {
	return &userAgentTransporter{
		userAgent:    "Docker-Client",
		routeTripper: cleanhttp.DefaultTransport(),
	}
}
