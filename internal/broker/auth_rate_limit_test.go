package broker

import (
	"context"
	"errors"
	"fmt"
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
		if _, err := a.Authenticate(context.Background(), "known", "incorrect-password"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("failed credential error=%v", err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "known", "incorrect-password"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("sixth failure error=%v", err)
	}
	if checks != 5 {
		t.Fatalf("rate-limited request reached password work: checks=%d", checks)
	}
	now = now.Add(5*time.Minute + time.Second)
	if _, err := a.Authenticate(context.Background(), "known", "incorrect-password"); !errors.Is(err, ErrUnauthenticated) || checks != 6 {
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
		username := fmt.Sprintf("unknown-%d", i)
		if _, err := a.Authenticate(context.Background(), username, "incorrect-password"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("username=%q error=%v", username, err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "known", "correct-password!"); err != nil {
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
		if _, err := a.Authenticate(context.Background(), "known", "correct-password!"); err != nil {
			t.Fatalf("valid credential was limited: %v", err)
		}
	}
}

func TestLocalAuthenticationDefaultSaturationCapacity(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{})
	if cap(a.passwordWork) != 2 || cap(a.passwordAdmission) != 8 {
		t.Fatalf("password workers=%d admissions=%d", cap(a.passwordWork), cap(a.passwordAdmission))
	}
}

func TestLocalAuthenticationQueuesUntilConfiguredSaturation(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 5, Window: time.Minute, Lockout: 5 * time.Minute, MaxConcurrent: 2, SaturationMultiplier: 2,
	})
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		entered <- struct{}{}
		<-release
		return false
	}

	results := make(chan error, 4)
	for _, username := range []string{"unknown-a", "unknown-b", "unknown-c", "unknown-d"} {
		go func() {
			_, err := a.Authenticate(context.Background(), username, "incorrect-password")
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("configured password workers did not start")
		}
	}
	waitForAuthenticationAdmissions(t, a, 4)
	if len(a.passwordWork) != 2 {
		t.Fatalf("concurrent password checks=%d", len(a.passwordWork))
	}
	if _, err := a.Authenticate(context.Background(), "unknown-e", "incorrect-password"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("saturated authentication error=%v", err)
	}
	close(release)
	for range 4 {
		select {
		case err := <-results:
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("admitted authentication error=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("admitted authentication did not finish")
		}
	}
	if len(entered) != 2 {
		t.Fatalf("queued password checks that eventually ran=%d", len(entered))
	}
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool { return false }
	for range 5 {
		if _, err := a.Authenticate(context.Background(), "unknown-e", "incorrect-password"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("saturation was incorrectly recorded as a password failure: %v", err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "unknown-e", "incorrect-password"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("per-username limiter did not activate after five real failures: %v", err)
	}
}

func TestQueuedLocalAuthenticationReleasesAdmissionOnCancellation(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 5, Window: time.Minute, Lockout: 5 * time.Minute, MaxConcurrent: 1, SaturationMultiplier: 2,
	})
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		entered <- struct{}{}
		<-release
		return false
	}
	first := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(context.Background(), "unknown-a", "incorrect-password")
		first <- err
	}()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		_, err := a.Authenticate(ctx, "unknown-b", "incorrect-password")
		second <- err
	}()
	waitForAuthenticationAdmissions(t, a, 2)
	cancel()
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled queued authentication error=%v", err)
	}
	waitForAuthenticationAdmissions(t, a, 1)
	close(release)
	if err := <-first; !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("active authentication error=%v", err)
	}
}

func TestQueuedLocalAuthenticationRechecksUsernameLockout(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 2, Window: time.Minute, Lockout: 5 * time.Minute, MaxConcurrent: 1, SaturationMultiplier: 3,
	})
	entered := make(chan struct{}, 3)
	permit := make(chan struct{})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		entered <- struct{}{}
		<-permit
		return false
	}
	results := make(chan error, 3)
	for range 3 {
		go func() {
			_, err := a.Authenticate(context.Background(), "known", "incorrect-password")
			results <- err
		}()
	}
	<-entered
	waitForAuthenticationAdmissions(t, a, 3)
	permit <- struct{}{}
	<-entered
	permit <- struct{}{}

	unauthenticated, limited := 0, 0
	for range 3 {
		select {
		case err := <-results:
			switch {
			case errors.Is(err, ErrUnauthenticated):
				unauthenticated++
			case errors.Is(err, ErrAuthenticationRateLimited):
				limited++
			default:
				t.Fatalf("queued authentication error=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("queued authentication did not finish")
		}
	}
	if unauthenticated != 2 || limited != 1 || len(entered) != 0 {
		t.Fatalf("unauthenticated=%d limited=%d extra password checks=%d", unauthenticated, limited, len(entered))
	}
}

func waitForAuthenticationAdmissions(t *testing.T, a *localPasswordAuthenticator, expected int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(a.passwordAdmission) != expected {
		if time.Now().After(deadline) {
			t.Fatalf("authentication admissions=%d, expected=%d", len(a.passwordAdmission), expected)
		}
		time.Sleep(time.Millisecond)
	}
}

func newRateLimitTestAuthenticator(t *testing.T, limit LocalAuthenticationRateLimit) *localPasswordAuthenticator {
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
	a, err := newLocalPasswordAuthenticator(context.Background(), AuthenticationConfig{
		TokenPepper: testPasswordPepper, LocalRateLimit: limit,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
