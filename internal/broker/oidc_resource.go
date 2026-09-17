package broker

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/rs/cors"
)

// requestedResourceKey carries a validated RFC 8707 resource indicator from the authorization
// handler to storage. The OpenID Provider library does not parse `resource` on an
// authorization request, so the value cannot travel inside its AuthRequest and is threaded
// through the request context instead.
type requestedResourceKeyType struct{}

var requestedResourceKey requestedResourceKeyType

var errUnknownResource = errors.New("invalid_target")

func withRequestedResource(ctx context.Context, resources []string) context.Context {
	return context.WithValue(ctx, requestedResourceKey, strings.Join(resources, " "))
}

// requestedResource returns the validated indicators as a single space separated value, which
// is how the grant persists them alongside the audience.
func requestedResource(ctx context.Context) string {
	resource, _ := ctx.Value(requestedResourceKey).(string)
	return resource
}

// validateRequestedResource checks an RFC 8707 indicator against what the operator configured.
//
// The configured list is the only source of truth. An empty list means the deployment never
// declared a resource, so no indicator can be honoured: the broker must not mint an audience
// for a URI an unauthenticated caller invented.
func validateRequestedResource(accepted []string, values []string) ([]string, error) {
	allowed := cleanStrings(accepted)
	resources := make([]string, 0, len(values))
	for _, value := range values {
		resource := strings.TrimSpace(value)
		if resource == "" {
			continue
		}
		parsed, err := url.Parse(resource)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
			return nil, errUnknownResource
		}
		if !slices.Contains(allowed, resource) {
			return nil, errUnknownResource
		}
		if len(resources) > 0 {
			// RFC 8707 permits several indicators, but this broker deliberately issues a
			// grant for one resource only. A multi-audience bearer token could be replayed
			// by either resource against the other one.
			return nil, errUnknownResource
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

// validateTokenRequestResource applies the broker's RFC 8707 policy at the token endpoint.
// Omitting resource keeps the authorization grant unchanged. If it is repeated, it must be
// the single target that was authorized earlier; the token request cannot widen or replace it.
func validateTokenRequestResource(accepted, values []string, granted string) error {
	resources, err := validateRequestedResource(accepted, values)
	if err != nil || len(resources) == 0 {
		return err
	}
	if resources[0] != strings.TrimSpace(granted) {
		return errUnknownResource
	}
	return nil
}

// resourceValues collects the `resource` parameter from wherever this request carries it.
func resourceValues(r *http.Request) []string {
	values := append([]string(nil), r.URL.Query()["resource"]...)
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			for _, value := range r.PostForm["resource"] {
				if !slices.Contains(values, value) {
					values = append(values, value)
				}
			}
		}
	}
	return values
}

// audienceFor returns the audiences a token is minted for.
//
// The broker's own audience is always present so the issued token keeps working against the
// broker's `/v1/*` API, and the requested resource is added so a resource server can verify
// the token was meant for it rather than replayed from somewhere else.
func audienceFor(brokerAudience string, resources ...string) []string {
	audience := []string{brokerAudience}
	for _, resource := range resources {
		for _, single := range strings.Fields(resource) {
			if single != "" && !slices.Contains(audience, single) {
				audience = append(audience, single)
			}
		}
	}
	return audience
}

// brokerCORSOptions turns the operator's declaration into the options the OpenID Provider
// library applies. Returning nil keeps the library from installing any CORS middleware at
// all, which is the fail-closed default.
func brokerCORSOptions(cfg CORSConfig) *cors.Options {
	origins := cleanStrings(cfg.AllowedOrigins)
	if len(origins) == 0 {
		return nil
	}
	return &cors.Options{
		AllowedOrigins: origins,
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedHeaders: []string{"Authorization", "Content-Type", "Accept", "Origin"},
		// A browser client reads the challenge from a failed request, so the header that
		// carries it has to be readable.
		ExposedHeaders:   []string{"WWW-Authenticate"},
		AllowCredentials: false,
	}
}
