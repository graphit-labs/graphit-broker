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
	"time"
)

func TestDatabaseConnectTimeoutConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, setting string
		want          time.Duration
	}{
		{"omitted", "", 15 * time.Second},
		{"configured", "  connect_timeout: 250ms\n", 250 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := DecodeConfig(strings.NewReader("database:\n  dsn: ':memory:'\n"+test.setting), func(string) string { return "" })
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Database.connectTimeout(); got != test.want {
				t.Fatalf("connect timeout = %s; want %s", got, test.want)
			}
		})
	}
	for _, setting := range []string{"0s", "-1s", "invalid"} {
		t.Run(setting, func(t *testing.T) {
			_, err := DecodeConfig(strings.NewReader("database:\n  dsn: ':memory:'\n  connect_timeout: "+setting+"\n"), func(string) string { return "" })
			if err == nil || (setting != "invalid" && !strings.Contains(err.Error(), "database.connect_timeout")) {
				t.Fatalf("connect_timeout %q accepted or error lacked field: %v", setting, err)
			}
		})
	}
}

func TestLoadConfigDatabaseEnvironmentRequiresYAMLReference(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BROKER_DATABASE_DRIVER", "postgres")
	t.Setenv("BROKER_DATABASE_DSN", "postgres://env.example/broker?sslmode=require")
	t.Setenv("CUSTOM_DATABASE_DRIVER", "mysql")
	t.Setenv("CUSTOM_DATABASE_DSN", "broker@tcp(custom.example:3306)/broker")
	for _, test := range []struct {
		name, input, driver, dsn string
	}{
		{"literal", "database:\n  driver: sqlite\n  dsn: /tmp/from-yaml.db\n", "sqlite", "/tmp/from-yaml.db"},
		{"configured fallback", "database:\n  dsn: ${IGNORED_DATABASE_DSN:-~/.graphit/broker/broker.db}\n", "sqlite", filepath.Join(home, ".graphit", "broker", "broker.db")},
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

func TestConfigChoosesDatabaseEnvironmentNameAndFallback(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, variable, value, want string
	}{
		{"fallback", "FIRST_SQLITE_PATH", "", filepath.Join(home, ".graphit", "broker", "broker.db")},
		{"first variable", "FIRST_SQLITE_PATH", filepath.Join(t.TempDir(), "first.db"), ""},
		{"second variable", "ANOTHER_SQLITE_PATH", filepath.Join(t.TempDir(), "second.db"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.want == "" {
				test.want = test.value
			}
			input := fmt.Sprintf("database:\n  driver: sqlite\n  dsn: ${%s:-~/.graphit/broker/broker.db}\n", test.variable)
			cfg, err := DecodeConfig(strings.NewReader(input), func(name string) string {
				if name != test.variable {
					t.Fatalf("unexpected environment lookup %q", name)
				}
				return test.value
			})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Database.DSN != test.want {
				t.Fatalf("SQLite DSN=%q, want %q", cfg.Database.DSN, test.want)
			}
		})
	}
}

func TestConfigRequiresDatabaseDSNWithoutConfiguredFallback(t *testing.T) {
	for _, input := range []string{"{}", "database: {driver: sqlite, dsn: ${EMPTY}}\n"} {
		if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil || err.Error() != "database.dsn is required" {
			t.Fatalf("input=%q error=%v", input, err)
		}
	}
}

func TestConfigChoosesModelDirectoryEnvironmentNameAndFallback(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, variable, value, want string
	}{
		{"fallback", "FIRST_MODELS_DIRECTORY", "", filepath.Join(home, ".graphit", "broker", "models")},
		{"first variable", "FIRST_MODELS_DIRECTORY", filepath.Join(t.TempDir(), "first-models"), ""},
		{"second variable", "ANOTHER_MODELS_DIRECTORY", filepath.Join(t.TempDir(), "second-models"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.want == "" {
				test.want = test.value
			}
			input := fmt.Sprintf(`
database: {dsn: ':memory:'}
services:
  embeddings:
    enabled: true
    upstream:
      protocol: onnx
      directory: ${%s:-~/.graphit/broker/models}
`, test.variable)
			cfg, err := DecodeConfig(strings.NewReader(input), func(name string) string {
				if name != test.variable {
					t.Fatalf("unexpected environment lookup %q", name)
				}
				return test.value
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Services.Embeddings.Upstream.Directory; got != test.want {
				t.Fatalf("models directory=%q, want %q", got, test.want)
			}
		})
	}
}

func TestConfigRequiresONNXDirectoryWithoutConfiguredFallback(t *testing.T) {
	for _, service := range []string{"embeddings", "rerank"} {
		input := fmt.Sprintf("database: {dsn: ':memory:'}\nservices: {%s: {enabled: true, upstream: {protocol: onnx}}}\n", service)
		if _, err := DecodeConfig(strings.NewReader(input), func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), "directory is required") {
			t.Fatalf("service=%s error=%v", service, err)
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
