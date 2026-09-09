package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestLocalAuthenticationRateLimitsPerUsernameBeforePasswordWork(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{})
	now := time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)
	a.rateLimiter.now = func() time.Time { return now }
	checks := 0
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		checks++
		return false
	}

	for range 5 {
		if _, err := a.Authenticate(context.Background(), "known:incorrect-password"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("failed credential error=%v", err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "known:incorrect-password"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("sixth failure error=%v", err)
	}
	if checks != 5 {
		t.Fatalf("rate-limited request reached password work: checks=%d", checks)
	}
	now = now.Add(5*time.Minute + time.Second)
	if _, err := a.Authenticate(context.Background(), "known:incorrect-password"); !errors.Is(err, ErrUnauthenticated) || checks != 6 {
		t.Fatalf("authentication did not resume after lockout: checks=%d err=%v", checks, err)
	}
}

func TestLocalAuthenticationDoesNotGloballyLimitFailures(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 2, Window: time.Minute, Lockout: 5 * time.Minute, MaxConcurrent: 2,
	})
	a.rateLimiter.now = func() time.Time { return time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC) }
	checks := 0
	a.passwordCheck = func(_ context.Context, _ passwordVerifier, _ []byte, password string) bool {
		checks++
		return password == "correct-password!"
	}
	for i := range 200 {
		credential := fmt.Sprintf("unknown-%d:incorrect-password", i)
		if _, err := a.Authenticate(context.Background(), credential); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("credential=%q error=%v", credential, err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "known:correct-password!"); err != nil {
		t.Fatalf("distinct failures caused a global block: %v", err)
	}
	if checks != 201 {
		t.Fatalf("password checks=%d", checks)
	}
}

func TestSuccessfulLocalAuthenticationDoesNotConsumeFailureQuota(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 2, Window: time.Minute, Lockout: 5 * time.Minute, MaxConcurrent: 2,
	})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool { return true }
	for range 20 {
		if _, err := a.Authenticate(context.Background(), "known:correct-password!"); err != nil {
			t.Fatalf("valid credential was limited: %v", err)
		}
	}
}

func TestLocalAuthenticationLimitsConcurrentPasswordWork(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{})
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		entered <- struct{}{}
		<-release
		return false
	}

	var wg sync.WaitGroup
	for _, credential := range []string{"unknown-a:incorrect-password", "unknown-b:incorrect-password"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = a.Authenticate(context.Background(), credential)
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("configured password workers did not start")
		}
	}
	if _, err := a.Authenticate(context.Background(), "unknown-c:incorrect-password"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("saturated authentication error=%v", err)
	}
	close(release)
	wg.Wait()
	if len(entered) != 0 {
		t.Fatalf("more than two password checks entered: queued=%d", len(entered))
	}
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool { return false }
	for range 5 {
		if _, err := a.Authenticate(context.Background(), "unknown-c:incorrect-password"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("saturation was incorrectly recorded as a password failure: %v", err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "unknown-c:incorrect-password"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("per-username limiter did not activate after five real failures: %v", err)
	}
}

func newRateLimitTestAuthenticator(t *testing.T, limit LocalAuthenticationRateLimit) *authenticator {
	t.Helper()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CreateLocalUser(context.Background(), LocalUser{
		Username: "known", Subject: "known", PasswordHash: mustPasswordHash(t, "correct-password!"), Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	a, err := newAuthenticator(context.Background(), AuthenticationConfig{
		TokenPepper: testPasswordPepper, LocalRateLimit: limit,
	}, store, false, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
