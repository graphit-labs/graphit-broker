package broker

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrAuthenticationRateLimited = errors.New("authentication rate limited")

const (
	localRateLimitDomain               = "graphit-broker/local-rate-limit/v1"
	maximumTrackedLoginNames           = 4096
	concurrentAuthenticationRetryAfter = time.Second
)

type authenticationRateLimitError struct {
	retryAfter time.Duration
}

func (e *authenticationRateLimitError) Error() string {
	return fmt.Sprintf("%s; retry after %s", ErrAuthenticationRateLimited, e.retryAfter.Round(time.Second))
}

func (e *authenticationRateLimitError) Unwrap() error { return ErrAuthenticationRateLimited }

func authenticationRetryAfter(err error) (time.Duration, bool) {
	var limited *authenticationRateLimitError
	if !errors.As(err, &limited) {
		return 0, false
	}
	return limited.retryAfter, true
}

type loginFailureWindow struct {
	startedAt    time.Time
	lastSeen     time.Time
	blockedUntil time.Time
	failures     int
}

type localPasswordRateLimiter struct {
	mu       sync.Mutex
	config   LocalAuthenticationRateLimit
	key      []byte
	accounts map[[sha256.Size]byte]loginFailureWindow
	now      func() time.Time
}

func newLocalPasswordRateLimiter(config LocalAuthenticationRateLimit, key []byte) *localPasswordRateLimiter {
	config.setDefaults()
	return &localPasswordRateLimiter{
		config: config, key: append([]byte(nil), key...),
		accounts: make(map[[sha256.Size]byte]loginFailureWindow), now: time.Now,
	}
}

func (l *localPasswordRateLimiter) allow(username string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := l.accountKey(username)
	entry := l.accounts[key]
	if retry := remainingLockout(entry, now); retry > 0 {
		return &authenticationRateLimitError{retryAfter: retry}
	}
	return nil
}

func (l *localPasswordRateLimiter) record(username string, authenticated bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := l.accountKey(username)
	if authenticated {
		delete(l.accounts, key)
		return
	}
	if len(l.accounts) >= maximumTrackedLoginNames {
		l.prune(now)
	}
	entry, tracked := l.accounts[key]
	if tracked || len(l.accounts) < maximumTrackedLoginNames {
		l.accounts[key] = addLoginFailure(entry, now, l.config.Window, l.config.MaxFailures, l.config.Lockout)
	}
}

func (l *localPasswordRateLimiter) accountKey(username string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write([]byte(localRateLimitDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(username))
	var key [sha256.Size]byte
	copy(key[:], mac.Sum(nil))
	return key
}

func (l *localPasswordRateLimiter) prune(now time.Time) {
	retention := l.config.Window + l.config.Lockout
	for key, entry := range l.accounts {
		if !entry.blockedUntil.After(now) && now.Sub(entry.lastSeen) > retention {
			delete(l.accounts, key)
		}
	}
}

func addLoginFailure(entry loginFailureWindow, now time.Time, window time.Duration, maximum int, lockout time.Duration) loginFailureWindow {
	if entry.startedAt.IsZero() || !now.Before(entry.startedAt.Add(window)) {
		entry.startedAt = now
		entry.failures = 0
	}
	entry.lastSeen = now
	entry.failures++
	if entry.failures >= maximum {
		entry.blockedUntil = now.Add(lockout)
	}
	return entry
}

func remainingLockout(entry loginFailureWindow, now time.Time) time.Duration {
	if entry.blockedUntil.After(now) {
		return entry.blockedUntil.Sub(now)
	}
	return 0
}
