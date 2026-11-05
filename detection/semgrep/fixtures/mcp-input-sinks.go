package fixtures

import (
	"errors"
	"net/url"
	"strings"
)

func validateEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	// ruleid: mcp-scheme-only-url-validation-go
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return errors.New("unsupported scheme")
	}
}

func validatePublicEndpoint(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	// ok: mcp-scheme-only-url-validation-go
	if u.Scheme == "https" && u.Hostname() == "public.example.invalid" {
		return nil
	}
	return errors.New("destination not permitted")
}
