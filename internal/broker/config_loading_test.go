package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigDatabaseEnvironmentRequiresYAMLReference(t *testing.T) {
	t.Setenv("BROKER_DATABASE_DRIVER", "postgres")
	t.Setenv("BROKER_DATABASE_DSN", "postgres://env.example/broker?sslmode=require")
	t.Setenv("CUSTOM_DATABASE_DRIVER", "mysql")
	t.Setenv("CUSTOM_DATABASE_DSN", "broker@tcp(custom.example:3306)/broker")
	for _, test := range []struct {
		name, input, driver, dsn string
	}{
		{"literal", "database:\n  driver: sqlite\n  dsn: /tmp/from-yaml.db\n", "sqlite", "/tmp/from-yaml.db"},
		{"defaults", "{}", "sqlite", "/var/lib/graphit-broker/broker.db"},
		{"explicit environment", "database:\n  driver: ${BROKER_DATABASE_DRIVER}\n  dsn: ${BROKER_DATABASE_DSN}\n", "postgres", "postgres://env.example/broker?sslmode=require"},
		{"custom environment names", "database:\n  driver: ${CUSTOM_DATABASE_DRIVER}\n  dsn: ${CUSTOM_DATABASE_DSN}\n", "mysql", "broker@tcp(custom.example:3306)/broker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(test.input), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Database.Driver != test.driver || cfg.Database.DSN != test.dsn {
				t.Fatalf("database = %q, %q; want %q, %q", cfg.Database.Driver, cfg.Database.DSN, test.driver, test.dsn)
			}
		})
	}
}

func TestDecodeConfigRequiredDatabaseEnvironment(t *testing.T) {
	input := "database:\n  driver: postgres\n  dsn: ${BROKER_DATABASE_DSN:?database DSN required}\n"
	for _, value := range []string{"", "postgres://env.example/broker"} {
		cfg, err := DecodeConfig(strings.NewReader(input), func(name string) string {
			if name != "BROKER_DATABASE_DSN" {
				t.Fatalf("unreferenced environment variable read: %s", name)
			}
			return value
		})
		if value == "" {
			if err == nil || !strings.Contains(err.Error(), "database DSN required") {
				t.Fatalf("missing required DSN error = %v", err)
			}
		} else if err != nil || cfg.Database.DSN != value {
			t.Fatalf("explicit DSN = %q, error = %v", cfg.Database.DSN, err)
		}
	}
}

func TestLoopbackHTTPConfigInitializesOIDCDiscovery(t *testing.T) {
	for _, origin := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		t.Run(origin, func(t *testing.T) {
			input := fmt.Sprintf(`
database:
  dsn: %q
server:
  public_url: %q
authentication:
  token_pepper: %q
administration:
  enabled: true
  cookie_secure: false
`, filepath.Join(t.TempDir(), "broker.db"), origin, testPasswordPepper)
			cfg, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" })
			if err != nil {
				t.Fatal(err)
			}
			server, err := NewServer(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, origin+"/.well-known/openid-configuration", nil))
			var metadata struct {
				Issuer                string `json:"issuer"`
				AuthorizationEndpoint string `json:"authorization_endpoint"`
				TokenEndpoint         string `json:"token_endpoint"`
			}
			if response.Code != http.StatusOK {
				t.Fatalf("discovery status = %d: %s", response.Code, response.Body.String())
			}
			if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.Issuer != origin || metadata.AuthorizationEndpoint != origin+"/oauth/authorize" || metadata.TokenEndpoint != origin+"/oauth/token" {
				t.Fatalf("unexpected discovery: %+v", metadata)
			}
		})
	}
}
