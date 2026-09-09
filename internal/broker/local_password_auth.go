package broker

import (
	"context"
	"fmt"
	"sync"
)

// localPasswordAuthenticator is deliberately separate from Authenticator: a
// primary password may establish a browser/OAuth login, but it is never an API
// bearer credential.
type localPasswordAuthenticator struct {
	localUsers        localUserReader
	tokenPepper       []byte
	dummy             passwordVerifier
	passwordWork      chan struct{}
	passwordAdmission chan struct{}
	admissionMu       sync.Mutex
	rateLimiter       *localPasswordRateLimiter
	captcha           localCaptchaVerifier
	captchaThreshold  int
	passwordCheck     func(context.Context, passwordVerifier, []byte, string) bool
}

func newLocalPasswordAuthenticator(ctx context.Context, cfg AuthenticationConfig, localUsers localUserReader, publicURLs ...string) (*localPasswordAuthenticator, error) {
	publicURL := ""
	if len(publicURLs) > 0 {
		publicURL = publicURLs[0]
	}
	cfg.LocalRateLimit.setDefaults()
	if err := cfg.LocalRateLimit.validate(); err != nil {
		return nil, err
	}
	cfg.LocalCaptcha.setDefaults()
	if err := cfg.LocalCaptcha.validate(cfg.LocalRateLimit, true, publicURL); err != nil {
		return nil, err
	}
	captcha, err := newLocalCaptchaVerifier(cfg.LocalCaptcha, publicURL)
	if err != nil {
		return nil, err
	}
	capacity := cfg.LocalRateLimit.MaxConcurrent * cfg.LocalRateLimit.SaturationMultiplier
	a := &localPasswordAuthenticator{
		localUsers: localUsers, tokenPepper: []byte(cfg.TokenPepper),
		passwordWork:      make(chan struct{}, cfg.LocalRateLimit.MaxConcurrent),
		passwordAdmission: make(chan struct{}, capacity),
		rateLimiter:       newLocalPasswordRateLimiter(cfg.LocalRateLimit, []byte(cfg.TokenPepper)),
		captcha:           captcha,
		captchaThreshold:  cfg.LocalCaptcha.threshold(cfg.LocalRateLimit.MaxConcurrent),
		passwordCheck:     verifyPassword,
	}
	if len(cfg.TokenPepper) >= tokenPepperMinimumBytes {
		dummyHash, err := HashPassword([]byte("graphit-broker-unknown-local-user"), []byte(cfg.TokenPepper))
		if err != nil {
			return nil, fmt.Errorf("initialize local password verifier: %w", err)
		}
		a.dummy, err = parsePasswordVerifier(dummyHash)
		if err != nil {
			return nil, fmt.Errorf("parse local password verifier: %w", err)
		}
	} else if counter, ok := localUsers.(interface {
		LocalUserCount(context.Context) (int, error)
	}); ok {
		count, err := counter.LocalUserCount(ctx)
		if err != nil {
			return nil, fmt.Errorf("count local users: %w", err)
		}
		if count > 0 {
			return nil, fmt.Errorf("authentication token pepper must contain at least %d bytes when local users exist", tokenPepperMinimumBytes)
		}
	}
	return a, nil
}

func (a *localPasswordAuthenticator) Authenticate(ctx context.Context, username, password string, captchaAttempts ...localCaptchaAttempt) (Principal, error) {
	captcha := localCaptchaAttempt{}
	if len(captchaAttempts) > 0 {
		captcha = captchaAttempts[0]
	}
	var user LocalUser
	var err error
	if a != nil && a.localUsers != nil {
		user, err = a.localUsers.LocalUserByUsername(ctx, username)
	}
	if err == nil && user.Enabled && user.Kind == humanIdentityKind {
		verifier, parseErr := parsePasswordVerifier(user.PasswordHash)
		if parseErr == nil {
			authenticated, checkErr := a.check(ctx, username, verifier, password, captcha)
			if checkErr != nil {
				return Principal{}, checkErr
			}
			if authenticated {
				return principalFromLocalUser(user, "local-password"), nil
			}
			return Principal{}, ErrUnauthenticated
		}
	}
	if a != nil && a.dummy.hash != nil {
		if _, checkErr := a.check(ctx, username, a.dummy, password, captcha); checkErr != nil {
			return Principal{}, checkErr
		}
	}
	return Principal{}, ErrUnauthenticated
}

func (a *localPasswordAuthenticator) check(ctx context.Context, username string, verifier passwordVerifier, password string, captcha localCaptchaAttempt) (bool, error) {
	if err := a.rateLimiter.allow(username); err != nil {
		return false, err
	}
	releaseAdmission, occupancy, err := a.acquirePasswordAdmission(ctx)
	if err != nil {
		return false, err
	}
	defer releaseAdmission()
	if a.captcha != nil && occupancy >= a.captchaThreshold {
		if err := a.captcha.Verify(ctx, captcha); err != nil {
			return false, newCaptchaRequiredError(a.captcha, captcha.Action)
		}
	}
	releaseWork, err := a.acquirePasswordWorker(ctx)
	if err != nil {
		return false, err
	}
	defer releaseWork()
	if err := a.rateLimiter.allow(username); err != nil {
		return false, err
	}
	authenticated := a.passwordCheck(ctx, verifier, a.tokenPepper, password)
	a.rateLimiter.record(username, authenticated)
	return authenticated, nil
}

func (a *localPasswordAuthenticator) acquirePasswordWork(ctx context.Context) (func(), error) {
	releaseAdmission, _, err := a.acquirePasswordAdmission(ctx)
	if err != nil {
		return nil, err
	}
	releaseWork, err := a.acquirePasswordWorker(ctx)
	if err != nil {
		releaseAdmission()
		return nil, err
	}
	return func() { releaseWork(); releaseAdmission() }, nil
}

func (a *localPasswordAuthenticator) acquirePasswordAdmission(ctx context.Context) (func(), int, error) {
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	default:
	}
	a.admissionMu.Lock()
	select {
	case a.passwordAdmission <- struct{}{}:
	default:
		a.admissionMu.Unlock()
		return nil, 0, &authenticationRateLimitError{retryAfter: concurrentAuthenticationRetryAfter}
	}
	occupancy := len(a.passwordAdmission)
	a.admissionMu.Unlock()
	return func() {
		a.admissionMu.Lock()
		<-a.passwordAdmission
		a.admissionMu.Unlock()
	}, occupancy, nil
}

func (a *localPasswordAuthenticator) acquirePasswordWorker(ctx context.Context) (func(), error) {
	select {
	case a.passwordWork <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return func() { <-a.passwordWork }, nil
}

func (a *localPasswordAuthenticator) CaptchaChallenge(action string) *localCaptchaChallenge {
	if a == nil || a.captcha == nil {
		return nil
	}
	a.admissionMu.Lock()
	required := len(a.passwordAdmission)+1 >= a.captchaThreshold
	a.admissionMu.Unlock()
	if !required {
		return nil
	}
	challenge := a.captcha.Challenge(action)
	return &challenge
}

func verifyPassword(_ context.Context, verifier passwordVerifier, pepper []byte, password string) bool {
	plaintext := []byte(password)
	defer clear(plaintext)
	return verifier.verify(plaintext, pepper)
}

func principalFromLocalUser(user LocalUser, method string) Principal {
	return Principal{Issuer: localIdentityIssuer, Subject: user.Subject, Name: user.Name, Email: user.Email,
		Username: user.Username, Organization: user.Organization, Teams: cleanStrings(user.Teams), Roles: user.Roles,
		LocalUserRevision: user.Revision, AuthMethod: method}
}
