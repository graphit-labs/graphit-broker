package broker

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	localChallengePrefix       = "gb_lc_"
	localChallengeTokenDomain  = "graphit-broker/local-auth-challenge/v1"
	localChallengeBindDomain   = "graphit-broker/local-auth-binding/v1"
	localMFAEncryptionDomain   = "graphit-broker/local-mfa-encryption/v1"
	localMFARecoveryCodeDomain = "graphit-broker/local-mfa-recovery/v1"
	localMFARateLimitDomain    = "graphit-broker/local-mfa-rate-limit/v1"

	localAuthPurposeAdmin  = "admin-login"
	localAuthPurposeOAuth  = "oauth-authorize"
	localAuthPurposeDevice = "device-approve"

	localAuthStagePassword = "password-change"
	localAuthStageMFA      = "mfa"
	localAuthStageEnroll   = "mfa-enrollment"

	localMFARecoveryCodeCount = 10
	localTOTPStepSeconds      = int64(30)
)

var (
	ErrLocalChallengeInvalid = errors.New("local authentication challenge is invalid or expired")
	ErrLocalMFACodeInvalid   = errors.New("MFA code is invalid")
)

type localAuthInputError struct{ message string }

func (e *localAuthInputError) Error() string { return e.message }

type LocalAuthStep struct {
	Status         string    `json:"status"`
	ChallengeToken string    `json:"challenge_token,omitempty"`
	Secret         string    `json:"secret,omitempty"`
	OTPAuthURI     string    `json:"otpauth_uri,omitempty"`
	QRCodeDataURL  string    `json:"qr_code_data_url,omitempty"`
	RecoveryCodes  []string  `json:"recovery_codes,omitempty"`
	Principal      Principal `json:"-"`
}

type storedLocalAuthChallenge struct {
	Hash              string
	Subject           string
	LocalUserRevision int64
	Purpose           string
	BindingHash       string
	Stage             string
	SecretCiphertext  string
	ExpiresAt         time.Time
}

type localAuthenticationService struct {
	store      *ControlStore
	config     LocalMFAConfig
	pepper     []byte
	passwords  *localPasswordAuthenticator
	mfaLimiter *localPasswordRateLimiter
	now        func() time.Time
}

func newLocalAuthenticationService(cfg AuthenticationConfig, store *ControlStore, passwords *localPasswordAuthenticator) (*localAuthenticationService, error) {
	if store == nil {
		return nil, nil
	}
	cfg.LocalMFA.setDefaults()
	if err := cfg.LocalMFA.validate(); err != nil {
		return nil, err
	}
	if len(cfg.TokenPepper) < tokenPepperMinimumBytes {
		return nil, fmt.Errorf("authentication token pepper must contain at least %d bytes", tokenPepperMinimumBytes)
	}
	rateKey := deriveLocalAuthKey([]byte(cfg.TokenPepper), localMFARateLimitDomain)
	return &localAuthenticationService{
		store: store, config: cfg.LocalMFA, pepper: []byte(cfg.TokenPepper), passwords: passwords,
		mfaLimiter: newLocalPasswordRateLimiter(cfg.LocalRateLimit, rateKey), now: time.Now,
	}, nil
}

func (a *localAuthenticationService) Begin(ctx context.Context, principal Principal, purpose, binding string) (LocalAuthStep, error) {
	if a == nil || principal.Issuer != localIdentityIssuer || principal.AuthMethod != "local-password" {
		return LocalAuthStep{}, ErrUnauthenticated
	}
	user, err := a.store.LocalUserBySubject(ctx, principal.Subject)
	if err != nil || !user.Enabled || user.Kind != humanIdentityKind || user.Revision != principal.LocalUserRevision {
		return LocalAuthStep{}, ErrUnauthenticated
	}
	if user.PasswordChangeRequired {
		return a.newChallenge(ctx, user, purpose, binding, localAuthStagePassword, "")
	}
	return a.advance(ctx, user, purpose, binding)
}

func (a *localAuthenticationService) advance(ctx context.Context, user LocalUser, purpose, binding string) (LocalAuthStep, error) {
	if !a.config.isRequired() {
		return LocalAuthStep{Status: "complete", Principal: principalFromLocalUser(user, "local-password")}, nil
	}
	if user.MFAEnabled {
		return a.newChallenge(ctx, user, purpose, binding, localAuthStageMFA, "")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: a.config.Issuer, AccountName: user.Username, Period: uint(localTOTPStepSeconds),
		SecretSize: 32, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return LocalAuthStep{}, fmt.Errorf("generate TOTP secret: %w", err)
	}
	ciphertext, err := a.encryptSecret(user.Subject, key.Secret())
	if err != nil {
		return LocalAuthStep{}, err
	}
	step, err := a.newChallenge(ctx, user, purpose, binding, localAuthStageEnroll, ciphertext)
	if err != nil {
		return LocalAuthStep{}, err
	}
	return a.enrollmentPresentation(step, key)
}

func (a *localAuthenticationService) enrollmentPresentation(step LocalAuthStep, key *otp.Key) (LocalAuthStep, error) {
	image, err := key.Image(256, 256)
	if err != nil {
		return LocalAuthStep{}, fmt.Errorf("render TOTP QR code: %w", err)
	}
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, image); err != nil {
		return LocalAuthStep{}, fmt.Errorf("encode TOTP QR code: %w", err)
	}
	step.Secret = key.Secret()
	step.OTPAuthURI = key.URL()
	step.QRCodeDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes.Bytes())
	return step, nil
}

func (a *localAuthenticationService) enrollmentPresentationForSecret(step LocalAuthStep, user LocalUser, secret string) (LocalAuthStep, error) {
	uri := &url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + a.config.Issuer + ":" + user.Username}
	query := uri.Query()
	query.Set("secret", secret)
	query.Set("issuer", a.config.Issuer)
	query.Set("period", fmt.Sprint(localTOTPStepSeconds))
	query.Set("digits", "6")
	query.Set("algorithm", "SHA1")
	uri.RawQuery = query.Encode()
	key, err := otp.NewKeyFromURL(uri.String())
	if err != nil {
		return LocalAuthStep{}, err
	}
	return a.enrollmentPresentation(step, key)
}

func (a *localAuthenticationService) CompletePasswordChange(ctx context.Context, raw, purpose, binding, newPassword string) (LocalAuthStep, error) {
	challenge, user, err := a.loadChallenge(ctx, raw, purpose, binding, localAuthStagePassword)
	if err != nil {
		return LocalAuthStep{}, err
	}
	password := []byte(newPassword)
	defer clear(password)
	if err := validatePassword(password); err != nil {
		return LocalAuthStep{}, &localAuthInputError{message: err.Error()}
	}
	if a.passwords == nil {
		return LocalAuthStep{}, errors.New("local password service is unavailable")
	}
	release, err := a.passwords.acquirePasswordWork(ctx)
	if err != nil {
		return LocalAuthStep{}, err
	}
	defer release()
	oldVerifier, err := parsePasswordVerifier(user.PasswordHash)
	if err != nil {
		return LocalAuthStep{}, ErrLocalChallengeInvalid
	}
	if oldVerifier.verify(password, a.pepper) {
		return LocalAuthStep{}, &localAuthInputError{message: "new password must differ from the current password"}
	}
	newHash, err := HashPassword(password, a.pepper)
	if err != nil {
		return LocalAuthStep{}, err
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalAuthStep{}, err
	}
	defer tx.Rollback()
	now := a.now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, a.store.bind(`UPDATE local_users SET password_hash=?, password_change_required=0, revision=revision+1, updated_at=? WHERE subject=? AND revision=? AND password_change_required=1`), newHash, now, user.Subject, challenge.LocalUserRevision)
	if err != nil {
		return LocalAuthStep{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return LocalAuthStep{}, ErrLocalChallengeInvalid
	}
	if err := a.store.invalidateLocalArtifactsTx(ctx, tx, user.Subject, now, purpose == localAuthPurposeDevice); err != nil {
		return LocalAuthStep{}, err
	}
	if err := tx.Commit(); err != nil {
		return LocalAuthStep{}, err
	}
	user, err = a.store.LocalUserBySubject(ctx, user.Subject)
	if err != nil {
		return LocalAuthStep{}, err
	}
	return a.advance(ctx, user, purpose, binding)
}

func (a *localAuthenticationService) CompleteMFA(ctx context.Context, raw, purpose, binding, code string) (LocalAuthStep, error) {
	challenge, user, err := a.loadChallenge(ctx, raw, purpose, binding, localAuthStageMFA, localAuthStageEnroll)
	if err != nil {
		return LocalAuthStep{}, err
	}
	if err := a.mfaLimiter.allow(user.Username); err != nil {
		return LocalAuthStep{}, err
	}
	now := a.now().UTC()
	if challenge.Stage == localAuthStageEnroll {
		secret, decryptErr := a.decryptSecret(user.Subject, challenge.SecretCiphertext)
		if decryptErr != nil {
			return LocalAuthStep{}, ErrLocalChallengeInvalid
		}
		acceptedStep, valid := validateTOTPAt(secret, code, now, -1)
		if !valid {
			a.mfaLimiter.record(user.Username, false)
			step, presentationErr := a.enrollmentPresentationForSecret(LocalAuthStep{Status: localAuthStageEnroll, ChallengeToken: raw}, user, secret)
			if presentationErr != nil {
				return LocalAuthStep{}, presentationErr
			}
			return step, ErrLocalMFACodeInvalid
		}
		recovery, err := a.enrollMFA(ctx, challenge, user, secret, acceptedStep, now)
		if err != nil {
			return LocalAuthStep{}, err
		}
		a.mfaLimiter.record(user.Username, true)
		user, err = a.store.LocalUserBySubject(ctx, user.Subject)
		if err != nil {
			return LocalAuthStep{}, err
		}
		return LocalAuthStep{Status: "complete", Principal: principalFromLocalUser(user, "local-password+totp"), RecoveryCodes: recovery}, nil
	}
	valid, err := a.consumeMFA(ctx, challenge, user, code, now)
	if err != nil {
		return LocalAuthStep{}, err
	}
	a.mfaLimiter.record(user.Username, valid)
	if !valid {
		return LocalAuthStep{Status: localAuthStageMFA, ChallengeToken: raw}, ErrLocalMFACodeInvalid
	}
	return LocalAuthStep{Status: "complete", Principal: principalFromLocalUser(user, "local-password+totp")}, nil
}

func (a *localAuthenticationService) newChallenge(ctx context.Context, user LocalUser, purpose, binding, stage, secretCiphertext string) (LocalAuthStep, error) {
	if !validLocalAuthPurpose(purpose) {
		return LocalAuthStep{}, errors.New("invalid local authentication purpose")
	}
	random, err := randomURLToken(32)
	if err != nil {
		return LocalAuthStep{}, err
	}
	raw := localChallengePrefix + random
	now := a.now().UTC()
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return LocalAuthStep{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, a.store.bind(`DELETE FROM local_auth_challenges WHERE subject=? AND purpose=?`), user.Subject, purpose); err != nil {
		return LocalAuthStep{}, err
	}
	_, err = tx.ExecContext(ctx, a.store.bind(`INSERT INTO local_auth_challenges(challenge_hash, subject, local_user_revision, purpose, binding_hash, stage, secret_ciphertext, expires_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.hash(localChallengeTokenDomain, raw), user.Subject, user.Revision, purpose, a.bindingHash(purpose, binding), stage, secretCiphertext, now.Add(a.config.ChallengeTTL).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return LocalAuthStep{}, err
	}
	if err := tx.Commit(); err != nil {
		return LocalAuthStep{}, err
	}
	return LocalAuthStep{Status: stage, ChallengeToken: raw}, nil
}

func (a *localAuthenticationService) loadChallenge(ctx context.Context, raw, purpose, binding string, allowedStages ...string) (storedLocalAuthChallenge, LocalUser, error) {
	if !strings.HasPrefix(raw, localChallengePrefix) || !validLocalAuthPurpose(purpose) {
		return storedLocalAuthChallenge{}, LocalUser{}, ErrLocalChallengeInvalid
	}
	var challenge storedLocalAuthChallenge
	var expires string
	err := a.store.db.QueryRowContext(ctx, a.store.bind(`SELECT challenge_hash, subject, local_user_revision, purpose, binding_hash, stage, secret_ciphertext, expires_at FROM local_auth_challenges WHERE challenge_hash=?`), a.hash(localChallengeTokenDomain, raw)).Scan(
		&challenge.Hash, &challenge.Subject, &challenge.LocalUserRevision, &challenge.Purpose, &challenge.BindingHash, &challenge.Stage, &challenge.SecretCiphertext, &expires)
	if err != nil {
		return storedLocalAuthChallenge{}, LocalUser{}, ErrLocalChallengeInvalid
	}
	challenge.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if challenge.Purpose != purpose || !constantEqual(challenge.BindingHash, a.bindingHash(purpose, binding)) || !challenge.ExpiresAt.After(a.now()) || !containsString(allowedStages, challenge.Stage) {
		return storedLocalAuthChallenge{}, LocalUser{}, ErrLocalChallengeInvalid
	}
	user, err := a.store.LocalUserBySubject(ctx, challenge.Subject)
	if err != nil || !user.Enabled || user.Kind != humanIdentityKind || user.Revision != challenge.LocalUserRevision {
		return storedLocalAuthChallenge{}, LocalUser{}, ErrLocalChallengeInvalid
	}
	return challenge, user, nil
}

func (a *localAuthenticationService) enrollMFA(ctx context.Context, challenge storedLocalAuthChallenge, user LocalUser, secret string, acceptedStep int64, now time.Time) ([]string, error) {
	ciphertext, err := a.encryptSecret(user.Subject, secret)
	if err != nil {
		return nil, err
	}
	codes, err := generateRecoveryCodes(localMFARecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nowText := now.Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, a.store.bind(`UPDATE local_users SET revision=revision+1, updated_at=? WHERE subject=? AND revision=?`), nowText, user.Subject, challenge.LocalUserRevision)
	if err != nil {
		return nil, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return nil, ErrLocalChallengeInvalid
	}
	if _, err := tx.ExecContext(ctx, a.store.bind(`INSERT INTO local_mfa(subject, secret_ciphertext, last_totp_step, confirmed_at) VALUES(?, ?, ?, ?)`), user.Subject, ciphertext, acceptedStep, nowText); err != nil {
		return nil, err
	}
	for _, code := range codes {
		if _, err := tx.ExecContext(ctx, a.store.bind(`INSERT INTO local_mfa_recovery_codes(subject, code_hash, created_at) VALUES(?, ?, ?)`), user.Subject, a.recoveryHash(user.Subject, code), nowText); err != nil {
			return nil, err
		}
	}
	if err := a.store.invalidateLocalArtifactsTx(ctx, tx, user.Subject, nowText, challenge.Purpose == localAuthPurposeDevice); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

func (a *localAuthenticationService) consumeMFA(ctx context.Context, challenge storedLocalAuthChallenge, user LocalUser, code string, now time.Time) (bool, error) {
	var ciphertext string
	var lastStep int64
	if err := a.store.db.QueryRowContext(ctx, a.store.bind(`SELECT secret_ciphertext, last_totp_step FROM local_mfa WHERE subject=?`), user.Subject).Scan(&ciphertext, &lastStep); err != nil {
		return false, ErrLocalChallengeInvalid
	}
	secret, err := a.decryptSecret(user.Subject, ciphertext)
	if err != nil {
		return false, ErrLocalChallengeInvalid
	}
	acceptedStep, totpValid := validateTOTPAt(secret, code, now, lastStep)
	recoveryHash := a.recoveryHash(user.Subject, code)
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	valid := false
	if totpValid {
		result, err := tx.ExecContext(ctx, a.store.bind(`UPDATE local_mfa SET last_totp_step=? WHERE subject=? AND last_totp_step<?`), acceptedStep, user.Subject, acceptedStep)
		if err != nil {
			return false, err
		}
		changed, _ := result.RowsAffected()
		valid = changed == 1
	} else if normalizedRecoveryCode(code) != "" {
		result, err := tx.ExecContext(ctx, a.store.bind(`DELETE FROM local_mfa_recovery_codes WHERE subject=? AND code_hash=?`), user.Subject, recoveryHash)
		if err != nil {
			return false, err
		}
		changed, _ := result.RowsAffected()
		valid = changed == 1
	}
	if !valid {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, a.store.bind(`DELETE FROM local_auth_challenges WHERE challenge_hash=? AND local_user_revision=?`), challenge.Hash, challenge.LocalUserRevision)
	if err != nil {
		return false, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return false, ErrLocalChallengeInvalid
	}
	return true, tx.Commit()
}

func (a *localAuthenticationService) encryptSecret(subject, secret string) (string, error) {
	block, err := aes.NewCipher(deriveLocalAuthKey(a.pepper, localMFAEncryptionDomain))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(secret), []byte(localMFAEncryptionDomain+"\x00"+subject))
	return "v1." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (a *localAuthenticationService) decryptSecret(subject, ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, "v1.") {
		return "", errors.New("unsupported MFA ciphertext")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ciphertext, "v1."))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveLocalAuthKey(a.pepper, localMFAEncryptionDomain))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < gcm.NonceSize() {
		return "", errors.New("invalid MFA ciphertext")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(localMFAEncryptionDomain+"\x00"+subject))
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return string(plain), nil
}

func (a *localAuthenticationService) hash(domain, value string) string {
	mac := hmac.New(sha256.New, a.pepper)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *localAuthenticationService) bindingHash(purpose, binding string) string {
	return a.hash(localChallengeBindDomain, purpose+"\x00"+binding)
}

func (a *localAuthenticationService) recoveryHash(subject, code string) string {
	return a.hash(localMFARecoveryCodeDomain, subject+"\x00"+normalizedRecoveryCode(code))
}

func deriveLocalAuthKey(pepper []byte, domain string) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(domain))
	return mac.Sum(nil)
}

func validateTOTPAt(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	current := now.Unix() / localTOTPStepSeconds
	opts := totp.ValidateOpts{Period: uint(localTOTPStepSeconds), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, step := range []int64{current, current - 1, current + 1} {
		if step <= lastStep || step < 0 {
			continue
		}
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(step*localTOTPStepSeconds, 0), opts)
		if err == nil && subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func generateRecoveryCodes(count int) ([]string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, 0, count)
	for len(codes) < count {
		random := make([]byte, 10)
		if _, err := rand.Read(random); err != nil {
			return nil, err
		}
		for i := range random {
			random[i] = alphabet[int(random[i])%len(alphabet)]
		}
		code := string(random[:5]) + "-" + string(random[5:])
		if !containsString(codes, code) {
			codes = append(codes, code)
		}
	}
	return codes, nil
}

func normalizedRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.NewReplacer("-", "", " ", "").Replace(code)
	if len(code) != 10 {
		return ""
	}
	for _, char := range code {
		if !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", char) {
			return ""
		}
	}
	return code
}

func validLocalAuthPurpose(purpose string) bool {
	return purpose == localAuthPurposeAdmin || purpose == localAuthPurposeOAuth || purpose == localAuthPurposeDevice
}

func (s *ControlStore) invalidateLocalArtifactsTx(ctx context.Context, tx *sql.Tx, subject, now string, preservePendingDevice bool) error {
	operations := []struct {
		query string
		args  []any
	}{
		{`UPDATE local_tokens SET revoked_at=? WHERE subject=? AND revoked_at=?`, []any{now, subject, ""}},
		{`DELETE FROM oidc_auth_requests WHERE identity_subject=?`, []any{subject}},
		{`DELETE FROM local_auth_challenges WHERE subject=?`, []any{subject}},
	}
	if !preservePendingDevice {
		operations = append(operations, struct {
			query string
			args  []any
		}{`DELETE FROM oauth_device_codes WHERE subject=?`, []any{subject}})
	}
	for _, operation := range operations {
		if _, err := tx.ExecContext(ctx, s.bind(operation.query), operation.args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *ControlStore) ResetLocalMFA(ctx context.Context, username string) error {
	user, err := s.LocalUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	if user.Kind != humanIdentityKind {
		return errors.New("service identities do not have MFA")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE local_users SET revision=revision+1, updated_at=? WHERE subject=? AND revision=?`), now, user.Subject, user.Revision)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrRevisionConflict
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM local_mfa WHERE subject=?`), user.Subject); err != nil {
		return err
	}
	if err := s.invalidateLocalArtifactsTx(ctx, tx, user.Subject, now, false); err != nil {
		return err
	}
	return tx.Commit()
}
