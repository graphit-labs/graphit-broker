package broker

import (
	"strings"
	"testing"
)

const testPasswordPepper = "password-pepper-0123456789abcdef"

func TestHashPasswordCreatesSaltedArgon2idVerifier(t *testing.T) {
	first, err := HashPassword([]byte("correct horse battery staple"), []byte(testPasswordPepper))
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword([]byte("correct horse battery staple"), []byte(testPasswordPepper))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("password verifiers reused a salt")
	}
	verifier, err := parsePasswordVerifier(first)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.verify([]byte("correct horse battery staple"), []byte(testPasswordPepper)) ||
		verifier.verify([]byte("wrong password"), []byte(testPasswordPepper)) ||
		verifier.verify([]byte("correct horse battery staple"), []byte("wrong-pepper-0123456789abcdefghi")) {
		t.Fatal("Argon2id verifier accepted the wrong password or rejected the correct password")
	}
}

func TestHashPasswordRequiresStrongPepper(t *testing.T) {
	for _, pepper := range []string{"", "too-short"} {
		if _, err := HashPassword([]byte("valid-password!"), []byte(pepper)); err == nil || !strings.Contains(err.Error(), "pepper") {
			t.Fatalf("pepper %q error=%v", pepper, err)
		}
	}
}

func TestHashPasswordRequiresFifteenUnicodeCharacters(t *testing.T) {
	for name, password := range map[string][]byte{
		"fourteen ASCII":   []byte(strings.Repeat("a", passwordMinimumCharacters-1)),
		"fourteen Unicode": []byte(strings.Repeat("á", passwordMinimumCharacters-1)),
		"invalid UTF-8":    {0xff, 0xfe},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := HashPassword(password, []byte(testPasswordPepper)); err == nil {
				t.Fatal("short or invalid password was accepted")
			}
		})
	}
	password := strings.Repeat("á", passwordMinimumCharacters)
	hash, err := HashPassword([]byte(password), []byte(testPasswordPepper))
	if err != nil {
		t.Fatalf("fifteen-character Unicode password was rejected: %v", err)
	}
	verifier, err := parsePasswordVerifier(hash)
	if err != nil || !verifier.verify([]byte(password), []byte(testPasswordPepper)) {
		t.Fatalf("Unicode verifier failed: %v", err)
	}
}

func TestParsePasswordVerifierRejectsUnsafeOrMalformedPHC(t *testing.T) {
	valid, err := HashPassword([]byte("correct horse battery staple"), []byte(testPasswordPepper))
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"algorithm":   strings.Replace(valid, "$argon2id$", "$argon2i$", 1),
		"version":     strings.Replace(valid, "$v=19$", "$v=16$", 1),
		"memory low":  strings.Replace(valid, "m=65536", "m=19456", 1),
		"memory high": strings.Replace(valid, "m=65536", "m=1048577", 1),
		"iterations":  strings.Replace(valid, "t=3", "t=2", 1),
		"parallelism": strings.Replace(valid, "p=4", "p=1", 1),
		"salt":        strings.Replace(valid, strings.Split(valid, "$")[4], "bad*base64", 1),
		"hash":        valid[:strings.LastIndex(valid, "$")+1] + "dGlueQ",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePasswordVerifier(encoded); err == nil {
				t.Fatalf("unsafe verifier accepted: %s", encoded)
			}
		})
	}
}

func mustPasswordHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := HashPassword([]byte(password), []byte(testPasswordPepper))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
