package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/graphit-labs/graphit-broker/internal/broker"
)

func TestHashPasswordFromStdinEmitsOnlyArgon2idVerifier(t *testing.T) {
	pepper := []byte("password-pepper-0123456789abcdef")
	for _, input := range []string{"automation-secret", "automation-secret\n", "automation-secret\r\n"} {
		var output bytes.Buffer
		if err := hashPasswordFromStdin(strings.NewReader(input), &output, pepper); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(output.String(), "$argon2id$") || strings.Contains(output.String(), "automation-secret") || strings.Count(output.String(), "\n") != 1 {
			t.Fatalf("unsafe output %q", output.String())
		}
		authenticator, err := broker.NewAuthenticator(context.Background(), broker.AuthenticationConfig{APIKeys: []broker.APIKeyConfig{{
			Username: "automation", PasswordHash: strings.TrimSpace(output.String()), Pepper: string(pepper), Subject: "automation",
		}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authenticator.Authenticate(context.Background(), "automation:automation-secret"); err != nil {
			t.Fatalf("generated verifier did not authenticate with its pepper: %v", err)
		}
	}
}

func TestHashPasswordFromStdinRejectsEmptyAndOversizedInput(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", 4097)} {
		var output bytes.Buffer
		if err := hashPasswordFromStdin(strings.NewReader(input), &output, []byte("password-pepper-0123456789abcdef")); err == nil || output.Len() != 0 {
			t.Fatalf("input length=%d error=%v output=%q", len(input), err, output.String())
		}
	}
}

func TestHashPasswordFromTerminalRejectsNonTerminalInput(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	defer read.Close()
	var prompt, output bytes.Buffer
	if err := hashPasswordFromTerminal(read, &prompt, &output, []byte("password-pepper-0123456789abcdef")); err == nil || output.Len() != 0 {
		t.Fatalf("non-terminal input error=%v output=%q", err, output.String())
	}
}

func TestPasswordPepperComesFromNamedEnvironmentVariable(t *testing.T) {
	lookup := func(name string) (string, bool) {
		if name == "BROKER_PASSWORD_PEPPER" {
			return "password-pepper-0123456789abcdef", true
		}
		return "", false
	}
	pepper, err := passwordPepperFromEnvironment("BROKER_PASSWORD_PEPPER", lookup)
	if err != nil || string(pepper) != "password-pepper-0123456789abcdef" {
		t.Fatalf("pepper=%q err=%v", pepper, err)
	}
	zeroBytes(pepper)
	for _, name := range []string{"", " MISSING", "MISSING", "SHORT"} {
		if _, err := passwordPepperFromEnvironment(name, func(candidate string) (string, bool) {
			if candidate == "SHORT" {
				return "too-short", true
			}
			return lookup(candidate)
		}); err == nil {
			t.Fatalf("pepper environment %q was accepted", name)
		}
	}
}
