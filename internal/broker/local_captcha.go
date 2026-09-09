package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	localCaptchaProviderTurnstile = "turnstile"
	localCaptchaProviderRecaptcha = "recaptcha"

	localCaptchaActionAdmin  = "admin-login"
	localCaptchaActionOAuth  = "oauth-login"
	localCaptchaActionDevice = "device-login"

	turnstileSiteverifyURL      = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	recaptchaSiteverifyURL      = "https://www.google.com/recaptcha/api/siteverify"
	maximumCaptchaResponseBytes = 2048
)

var ErrLocalCaptchaRequired = errors.New("human verification is required")

type localCaptchaAttempt struct {
	Token  string
	Action string
}

type localCaptchaChallenge struct {
	Provider string `json:"provider"`
	SiteKey  string `json:"site_key"`
	Action   string `json:"action,omitempty"`
}

type localCaptchaRequiredError struct {
	challenge localCaptchaChallenge
}

func (e *localCaptchaRequiredError) Error() string { return ErrLocalCaptchaRequired.Error() }
func (e *localCaptchaRequiredError) Unwrap() error { return ErrLocalCaptchaRequired }

func captchaChallengeFromError(err error) (localCaptchaChallenge, bool) {
	var required *localCaptchaRequiredError
	if !errors.As(err, &required) {
		return localCaptchaChallenge{}, false
	}
	return required.challenge, true
}

type localCaptchaVerifier interface {
	Verify(context.Context, localCaptchaAttempt) error
	Challenge(string) localCaptchaChallenge
}

type captchaHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type remoteLocalCaptchaVerifier struct {
	provider         string
	siteKey          string
	secretKey        string
	expectedHostname string
	endpoint         string
	timeout          time.Duration
	client           captchaHTTPClient
}

func newLocalCaptchaVerifier(config LocalCaptchaConfig, publicURL string) (localCaptchaVerifier, error) {
	if !config.Enabled {
		return nil, nil
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("parse server.public_url hostname for local CAPTCHA")
	}
	endpoint := turnstileSiteverifyURL
	if config.Provider == localCaptchaProviderRecaptcha {
		endpoint = recaptchaSiteverifyURL
	}
	return &remoteLocalCaptchaVerifier{
		provider: config.Provider, siteKey: strings.TrimSpace(config.SiteKey), secretKey: strings.TrimSpace(config.SecretKey),
		expectedHostname: parsed.Hostname(), endpoint: endpoint, timeout: config.VerificationTimeout,
		client: &http.Client{Transport: http.DefaultTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

func (v *remoteLocalCaptchaVerifier) Challenge(action string) localCaptchaChallenge {
	challenge := localCaptchaChallenge{Provider: v.provider, SiteKey: v.siteKey}
	if v.provider == localCaptchaProviderTurnstile {
		challenge.Action = action
	}
	return challenge
}

func (v *remoteLocalCaptchaVerifier) Verify(ctx context.Context, attempt localCaptchaAttempt) error {
	token := strings.TrimSpace(attempt.Token)
	if token == "" || len(token) > maximumCaptchaResponseBytes {
		return ErrLocalCaptchaRequired
	}
	verifyContext, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	form := url.Values{"secret": {v.secretKey}, "response": {token}}
	request, err := http.NewRequestWithContext(verifyContext, http.MethodPost, v.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrLocalCaptchaRequired
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := v.client.Do(request)
	if err != nil {
		return ErrLocalCaptchaRequired
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ErrLocalCaptchaRequired
	}
	var result struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&result); err != nil {
		return ErrLocalCaptchaRequired
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrLocalCaptchaRequired
	}
	if !result.Success || !strings.EqualFold(strings.TrimSpace(result.Hostname), v.expectedHostname) {
		return ErrLocalCaptchaRequired
	}
	if v.provider == localCaptchaProviderTurnstile && result.Action != attempt.Action {
		return ErrLocalCaptchaRequired
	}
	return nil
}

func newCaptchaRequiredError(verifier localCaptchaVerifier, action string) error {
	return &localCaptchaRequiredError{challenge: verifier.Challenge(action)}
}

func localCaptchaScriptSources(config LocalCaptchaConfig) string {
	if !config.Enabled {
		return ""
	}
	if config.Provider == localCaptchaProviderTurnstile {
		return " https://challenges.cloudflare.com"
	}
	return " https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/"
}

func localCaptchaFrameSources(config LocalCaptchaConfig) string {
	if !config.Enabled {
		return "'none'"
	}
	if config.Provider == localCaptchaProviderTurnstile {
		return "https://challenges.cloudflare.com"
	}
	return "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"
}

func localCaptchaConnectSources(config LocalCaptchaConfig) string {
	if !config.Enabled || config.Provider == localCaptchaProviderTurnstile {
		return ""
	}
	return " https://www.google.com/recaptcha/"
}
