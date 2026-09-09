package broker

import (
	"context"
	"fmt"
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
	rateLimiter       *localPasswordRateLimiter
	passwordCheck     func(context.Context, passwordVerifier, []byte, string) bool
}

func newLocalPasswordAuthenticator(ctx context.Context, cfg AuthenticationConfig, localUsers localUserReader) (*localPasswordAuthenticator, error) {
	cfg.LocalRateLimit.setDefaults()
	if err := cfg.LocalRateLimit.validate(); err != nil {
		return nil, err
	}
	capacity := cfg.LocalRateLimit.MaxConcurrent * cfg.LocalRateLimit.SaturationMultiplier
	a := &localPasswordAuthenticator{
		localUsers: localUsers, tokenPepper: []byte(cfg.TokenPepper),
		passwordWork:      make(chan struct{}, cfg.LocalRateLimit.MaxConcurrent),
		passwordAdmission: make(chan struct{}, capacity),
		rateLimiter:       newLocalPasswordRateLimiter(cfg.LocalRateLimit, []byte(cfg.TokenPepper)),
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

func (a *localPasswordAuthenticator) Authenticate(ctx context.Context, username, password string) (Principal, error) {
	var user LocalUser
	var err error
	if a != nil && a.localUsers != nil {
		user, err = a.localUsers.LocalUserByUsername(ctx, username)
	}
	if err == nil && user.Enabled && user.Kind == humanIdentityKind {
		verifier, parseErr := parsePasswordVerifier(user.PasswordHash)
		if parseErr == nil {
			authenticated, checkErr := a.check(ctx, username, verifier, password)
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
		if _, checkErr := a.check(ctx, username, a.dummy, password); checkErr != nil {
			return Principal{}, checkErr
		}
	}
	return Principal{}, ErrUnauthenticated
}

func (a *localPasswordAuthenticator) check(ctx context.Context, username string, verifier passwordVerifier, password string) (bool, error) {
	if err := a.rateLimiter.allow(username); err != nil {
		return false, err
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	select {
	case a.passwordAdmission <- struct{}{}:
		defer func() { <-a.passwordAdmission }()
	default:
		return false, &authenticationRateLimitError{retryAfter: concurrentAuthenticationRetryAfter}
	}
	select {
	case a.passwordWork <- struct{}{}:
		defer func() { <-a.passwordWork }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	if err := a.rateLimiter.allow(username); err != nil {
		return false, err
	}
	authenticated := a.passwordCheck(ctx, verifier, a.tokenPepper, password)
	a.rateLimiter.record(username, authenticated)
	return authenticated, nil
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
