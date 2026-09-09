package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/graphit-labs/graphit-broker/internal/broker"
)

const testPepper = "password-pepper-0123456789abcdef"

func TestPasswordFromStdinAcceptsOneSecretWithoutEcho(t *testing.T) {
	for _, input := range []string{"automation-secret", "automation-secret\n", "automation-secret\r\n"} {
		password, err := passwordFromStdin(strings.NewReader(input))
		if err != nil || string(password) != "automation-secret" {
			t.Fatalf("password=%q err=%v", password, err)
		}
		zeroBytes(password)
	}
}

func TestPasswordFromStdinRejectsEmptyAndOversizedInput(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", 4097)} {
		if password, err := passwordFromStdin(strings.NewReader(input)); err == nil || password != nil {
			t.Fatalf("input length=%d error=%v password=%q", len(input), err, password)
		}
	}
}

func TestPasswordFromTerminalRejectsNonTerminalInput(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	defer read.Close()
	var prompt bytes.Buffer
	if password, err := passwordFromTerminal(read, &prompt); err == nil || password != nil {
		t.Fatalf("non-terminal input error=%v password=%q", err, password)
	}
}

func TestBootstrapLocalAdminCreatesOnlyTheFirstAdministrator(t *testing.T) {
	cfg := broker.Config{
		Database:       broker.DatabaseConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "broker.db"), MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute},
		Authentication: broker.AuthenticationConfig{TokenPepper: testPepper},
	}
	if err := bootstrapLocalAdmin(context.Background(), cfg, []byte("short-password")); err == nil {
		t.Fatal("bootstrap accepted a password shorter than 15 characters")
	}
	password := []byte("administrator-secret")
	if err := bootstrapLocalAdmin(context.Background(), cfg, password); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapLocalAdmin(context.Background(), cfg, []byte("replacement-secret")); err == nil {
		t.Fatal("second bootstrap overwrote the existing local administrator")
	}
	store, err := broker.OpenControlStore(cfg.Database, cfg.Authentication.TokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	users, err := store.LocalUsers(context.Background())
	if err != nil || len(users) != 1 || users[0].Username != "admin" || users[0].Subject != "admin" || !contains(users[0].Roles, "admin") || !contains(users[0].Roles, "user") {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	authenticator, err := broker.NewAuthenticator(context.Background(), cfg.Authentication, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(context.Background(), "admin:administrator-secret"); err == nil {
		t.Fatal("bootstrapped administrator password was accepted as a bearer credential")
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
