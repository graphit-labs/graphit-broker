package broker

import (
	"net/http"
	"strings"
	"testing"
)

func TestBrokerCORSOptionsFailClosed(t *testing.T) {
	// No declared origin means the library installs no CORS middleware at all, which is the
	// behaviour the broker had before the setting existed.
	if got := brokerCORSOptions(CORSConfig{}); got != nil {
		t.Fatalf("brokerCORSOptions with no origins = %#v; want nil", got)
	}
	if got := brokerCORSOptions(CORSConfig{AllowedOrigins: []string{"  ", ""}}); got != nil {
		t.Fatalf("brokerCORSOptions with blank origins = %#v; want nil", got)
	}

	options := brokerCORSOptions(CORSConfig{AllowedOrigins: []string{"https://claude.ai"}})
	if options == nil {
		t.Fatal("a declared origin produced no options")
	}
	if options.AllowCredentials {
		// OAuth here authenticates with the Authorization header, so credentials stay off and
		// the invalid wildcard-plus-credentials pair cannot be configured.
		t.Error("credentials are enabled; the wildcard pair would become representable")
	}
	if !strings.Contains(strings.Join(options.AllowedHeaders, ","), "Authorization") {
		t.Errorf("allowed headers = %v; want Authorization", options.AllowedHeaders)
	}
	if !strings.Contains(strings.Join(options.ExposedHeaders, ","), "WWW-Authenticate") {
		t.Errorf("exposed headers = %v; a browser client could not read the challenge", options.ExposedHeaders)
	}
}

func TestBrokerOAuthEndpointsHonourDeclaredOrigins(t *testing.T) {
	_, httpServer := newResourceTestServerWithCORS(t, []string{"https://claude.ai"})

	response, err := http.DefaultClient.Do(mustRequest(t, http.MethodGet, httpServer.URL+"/.well-known/openid-configuration", "https://claude.ai"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Access-Control-Allow-Origin"); got != "https://claude.ai" {
		t.Errorf("Access-Control-Allow-Origin = %q; want the declared origin", got)
	}

	refused, err := http.DefaultClient.Do(mustRequest(t, http.MethodGet, httpServer.URL+"/.well-known/openid-configuration", "https://attacker.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Body.Close()
	if got := refused.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q for an undeclared origin; want none", got)
	}
}

func TestBrokerOAuthEndpointsEmitNoCORSWhenUndeclared(t *testing.T) {
	_, httpServer := newResourceTestServerWithCORS(t, nil)

	response, err := http.DefaultClient.Do(mustRequest(t, http.MethodGet, httpServer.URL+"/.well-known/openid-configuration", "https://claude.ai"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q; want none when no origin is declared", got)
	}
}

func mustRequest(t *testing.T, method, url, origin string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	return request
}
