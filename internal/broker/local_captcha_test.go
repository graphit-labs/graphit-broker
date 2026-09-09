package broker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type stubLocalCaptchaVerifier struct {
	provider string
	valid    string
	entered  chan struct{}
	release  <-chan struct{}

	mu       sync.Mutex
	attempts []localCaptchaAttempt
}

func (v *stubLocalCaptchaVerifier) Verify(ctx context.Context, attempt localCaptchaAttempt) error {
	v.mu.Lock()
	v.attempts = append(v.attempts, attempt)
	v.mu.Unlock()
	if v.entered != nil {
		v.entered <- struct{}{}
	}
	if v.release != nil {
		select {
		case <-v.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if attempt.Token != v.valid {
		return ErrLocalCaptchaRequired
	}
	return nil
}

func (v *stubLocalCaptchaVerifier) Challenge(action string) localCaptchaChallenge {
	challenge := localCaptchaChallenge{Provider: v.provider, SiteKey: "site-key"}
	if v.provider == localCaptchaProviderTurnstile {
		challenge.Action = action
	}
	return challenge
}

func (v *stubLocalCaptchaVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.attempts)
}

func TestRemoteLocalCaptchaVerifierSupportsTurnstileAndRecaptcha(t *testing.T) {
	for _, test := range []struct {
		provider string
		response string
		action   string
	}{
		{provider: localCaptchaProviderTurnstile, response: `{"success":true,"hostname":"broker.example.com","action":"admin-login"}`, action: localCaptchaActionAdmin},
		{provider: localCaptchaProviderRecaptcha, response: `{"success":true,"hostname":"broker.example.com"}`, action: localCaptchaActionAdmin},
	} {
		t.Run(test.provider, func(t *testing.T) {
			var received url.Values
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
					t.Errorf("Siteverify request method=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					http.Error(w, "invalid form", http.StatusBadRequest)
					return
				}
				received = r.PostForm
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()

			verifier := &remoteLocalCaptchaVerifier{
				provider: test.provider, siteKey: "site-key", secretKey: "secret-key", expectedHostname: "broker.example.com",
				endpoint: server.URL, timeout: time.Second, client: server.Client(),
			}
			if err := verifier.Verify(context.Background(), localCaptchaAttempt{Token: "proof-token", Action: test.action}); err != nil {
				t.Fatalf("valid %s proof failed: %v", test.provider, err)
			}
			if received.Get("secret") != "secret-key" || received.Get("response") != "proof-token" || received.Has("remoteip") {
				t.Fatalf("Siteverify form=%#v", received)
			}
		})
	}
}

func TestRemoteLocalCaptchaVerifierFailsClosed(t *testing.T) {
	for name, response := range map[string]string{
		"provider rejection": `{"success":false,"hostname":"broker.example.com"}`,
		"wrong hostname":     `{"success":true,"hostname":"other.example.com","action":"admin-login"}`,
		"wrong action":       `{"success":true,"hostname":"broker.example.com","action":"device-login"}`,
		"malformed response": `{`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(response)) }))
			defer server.Close()
			verifier := &remoteLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, secretKey: "secret", expectedHostname: "broker.example.com", endpoint: server.URL, timeout: time.Second, client: server.Client()}
			if err := verifier.Verify(context.Background(), localCaptchaAttempt{Token: "proof", Action: localCaptchaActionAdmin}); !errors.Is(err, ErrLocalCaptchaRequired) {
				t.Fatalf("verification error=%v", err)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"success":true,"hostname":"broker.example.com","action":"admin-login"}`))
	}))
	defer server.Close()
	verifier := &remoteLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, secretKey: "secret", expectedHostname: "broker.example.com", endpoint: server.URL, timeout: 10 * time.Millisecond, client: server.Client()}
	if err := verifier.Verify(context.Background(), localCaptchaAttempt{Token: "proof", Action: localCaptchaActionAdmin}); !errors.Is(err, ErrLocalCaptchaRequired) {
		t.Fatalf("timeout verification error=%v", err)
	}

	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirector := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirector.Close()
	config := LocalCaptchaConfig{Enabled: true, Provider: localCaptchaProviderTurnstile, SiteKey: "site", SecretKey: "secret", TriggerMultiplier: 1.5, VerificationTimeout: time.Second}
	configured, err := newLocalCaptchaVerifier(config, "https://broker.example.com")
	if err != nil {
		t.Fatal(err)
	}
	remote := configured.(*remoteLocalCaptchaVerifier)
	remote.endpoint = redirector.URL
	if err := remote.Verify(context.Background(), localCaptchaAttempt{Token: "proof", Action: localCaptchaActionAdmin}); !errors.Is(err, ErrLocalCaptchaRequired) || redirected.Load() != 0 {
		t.Fatalf("redirect verification error=%v redirected_requests=%d", err, redirected.Load())
	}
}

func TestLocalCaptchaStartsAtConfiguredConcurrentThresholdBeforePasswordWork(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: 2, SaturationMultiplier: 4,
	})
	verifier := &stubLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, valid: "valid-proof", entered: make(chan struct{}, 2)}
	a.captcha = verifier
	a.captchaThreshold = 3
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		entered <- struct{}{}
		<-release
		return false
	}
	results := make(chan error, 3)
	for _, username := range []string{"unknown-a", "unknown-b"} {
		go func() {
			_, err := a.Authenticate(context.Background(), username, "incorrect-password")
			results <- err
		}()
	}
	for range 2 {
		<-entered
	}
	if challenge := a.CaptchaChallenge(localCaptchaActionAdmin); challenge == nil || challenge.Action != localCaptchaActionAdmin {
		t.Fatalf("next-attempt challenge=%#v", challenge)
	}
	if _, err := a.Authenticate(context.Background(), "unknown-c", "incorrect-password"); !errors.Is(err, ErrLocalCaptchaRequired) {
		t.Fatalf("third authentication error=%v", err)
	}
	<-verifier.entered
	if verifier.callCount() != 1 || len(entered) != 0 {
		t.Fatalf("CAPTCHA calls=%d unexpected password checks=%d", verifier.callCount(), len(entered))
	}
	go func() {
		_, err := a.Authenticate(context.Background(), "unknown-c", "incorrect-password", localCaptchaAttempt{Token: "valid-proof", Action: localCaptchaActionAdmin})
		results <- err
	}()
	<-verifier.entered
	close(release)
	for range 3 {
		if err := <-results; !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("authentication result=%v", err)
		}
	}
	if challenge := a.CaptchaChallenge(localCaptchaActionAdmin); challenge != nil {
		t.Fatalf("challenge remained after pressure ended: %#v", challenge)
	}
}

func TestLocalCaptchaZeroMultiplierRequiresProofFromFirstAttempt(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: 2, SaturationMultiplier: 4,
	})
	a.captcha = &stubLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, valid: "valid-proof"}
	a.captchaThreshold = (LocalCaptchaConfig{TriggerMultiplier: 0}).threshold(2)
	var passwordChecks atomic.Int32
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		passwordChecks.Add(1)
		return false
	}

	if challenge := a.CaptchaChallenge(localCaptchaActionAdmin); challenge == nil {
		t.Fatal("first attempt did not advertise required CAPTCHA")
	}
	if _, err := a.Authenticate(context.Background(), "unknown", "incorrect-password"); !errors.Is(err, ErrLocalCaptchaRequired) {
		t.Fatalf("authentication without CAPTCHA error=%v", err)
	}
	if passwordChecks.Load() != 0 {
		t.Fatalf("password checks before CAPTCHA=%d", passwordChecks.Load())
	}
	if _, err := a.Authenticate(context.Background(), "unknown", "incorrect-password", localCaptchaAttempt{Token: "valid-proof", Action: localCaptchaActionAdmin}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("authentication with CAPTCHA error=%v", err)
	}
	if passwordChecks.Load() != 1 {
		t.Fatalf("password checks after CAPTCHA=%d", passwordChecks.Load())
	}
}

func TestLocalCaptchaFractionalMultiplierStartsBeforeWorkerLimit(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: 4, SaturationMultiplier: 4,
	})
	a.captcha = &stubLocalCaptchaVerifier{provider: localCaptchaProviderTurnstile, valid: "valid-proof"}
	a.captchaThreshold = (LocalCaptchaConfig{TriggerMultiplier: .5}).threshold(4)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	a.passwordCheck = func(context.Context, passwordVerifier, []byte, string) bool {
		entered <- struct{}{}
		<-release
		return false
	}
	result := make(chan error, 1)

	if challenge := a.CaptchaChallenge(localCaptchaActionAdmin); challenge != nil {
		t.Fatalf("first attempt unexpectedly requires CAPTCHA: %#v", challenge)
	}
	go func() {
		_, err := a.Authenticate(context.Background(), "unknown-a", "incorrect-password")
		result <- err
	}()
	<-entered
	if challenge := a.CaptchaChallenge(localCaptchaActionAdmin); challenge == nil {
		t.Fatal("second attempt did not advertise required CAPTCHA")
	}
	if _, err := a.Authenticate(context.Background(), "unknown-b", "incorrect-password"); !errors.Is(err, ErrLocalCaptchaRequired) {
		t.Fatalf("second authentication error=%v", err)
	}
	if len(entered) != 0 {
		t.Fatal("second attempt reached password check")
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("first authentication result=%v", err)
	}
}

func TestLocalCaptchaVerificationUsesBoundedAuthenticationAdmission(t *testing.T) {
	a := newRateLimitTestAuthenticator(t, LocalAuthenticationRateLimit{
		MaxFailures: 5, Window: time.Minute, Lockout: time.Minute, MaxConcurrent: 1, SaturationMultiplier: 4,
	})
	release := make(chan struct{})
	verifier := &stubLocalCaptchaVerifier{provider: localCaptchaProviderRecaptcha, valid: "valid-proof", entered: make(chan struct{}, 4), release: release}
	a.captcha = verifier
	a.captchaThreshold = 1
	results := make(chan error, 4)
	for i := range 4 {
		go func() {
			_, err := a.Authenticate(context.Background(), "unknown-"+string(rune('a'+i)), "incorrect-password", localCaptchaAttempt{Token: "valid-proof", Action: localCaptchaActionAdmin})
			results <- err
		}()
	}
	for range 4 {
		<-verifier.entered
	}
	if _, err := a.Authenticate(context.Background(), "unknown-e", "incorrect-password", localCaptchaAttempt{Token: "valid-proof", Action: localCaptchaActionAdmin}); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("authentication beyond bounded CAPTCHA verification error=%v", err)
	}
	if verifier.callCount() != 4 {
		t.Fatalf("unbounded CAPTCHA calls=%d", verifier.callCount())
	}
	close(release)
	for range 4 {
		if err := <-results; !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("admitted result=%v", err)
		}
	}
}
