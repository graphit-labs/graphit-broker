package broker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestLocalAuthenticationRequiresPasswordChangeThenMFAAndStoresOnlyProtectedValues(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateLocalUser(ctx, LocalUser{Username: "alice", Subject: "alice-subject", Kind: humanIdentityKind,
		PasswordHash: mustPasswordHash(t, "temporary-password"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	cfg := AuthenticationConfig{TokenPepper: testPasswordPepper}
	passwords, err := newLocalPasswordAuthenticator(ctx, cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	service, err := newLocalAuthenticationService(cfg, store, passwords)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return fixed }
	principal, err := passwords.Authenticate(ctx, "alice", "temporary-password")
	if err != nil {
		t.Fatal(err)
	}
	step, err := service.Begin(ctx, principal, localAuthPurposeAdmin, "")
	if err != nil || step.Status != localAuthStagePassword || !strings.HasPrefix(step.ChallengeToken, localChallengePrefix) {
		t.Fatalf("password step=%#v err=%v", step, err)
	}
	if _, err := service.CompletePasswordChange(ctx, step.ChallengeToken, localAuthPurposeOAuth, "", "permanent-password"); !errors.Is(err, ErrLocalChallengeInvalid) {
		t.Fatalf("challenge crossed purpose boundary: %v", err)
	}
	if _, err := service.CompletePasswordChange(ctx, step.ChallengeToken, localAuthPurposeAdmin, "", "temporary-password"); err == nil {
		t.Fatal("current password was accepted as replacement")
	}
	step, err = service.CompletePasswordChange(ctx, step.ChallengeToken, localAuthPurposeAdmin, "", "permanent-password")
	if err != nil || step.Status != localAuthStageEnroll || step.Secret == "" || step.QRCodeDataURL == "" || !strings.HasPrefix(step.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("enrollment step=%#v err=%v", step, err)
	}
	var rendered bytes.Buffer
	if err := localAuthorizationPage.Execute(&rendered, loginPageData(step, "")); err != nil || !strings.Contains(rendered.String(), `src="data:image/png;base64,`) || strings.Contains(rendered.String(), "#ZgotmplZ") {
		t.Fatalf("enrollment QR did not render safely: err=%v", err)
	}
	var rawChallenge, rawSecret int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM local_auth_challenges WHERE challenge_hash=?`, step.ChallengeToken).Scan(&rawChallenge); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM local_auth_challenges WHERE secret_ciphertext LIKE ?`, "%"+step.Secret+"%").Scan(&rawSecret); err != nil {
		t.Fatal(err)
	}
	if rawChallenge != 0 || rawSecret != 0 {
		t.Fatalf("raw challenge=%d raw secret=%d", rawChallenge, rawSecret)
	}
	code, err := totp.GenerateCode(step.Secret, fixed)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := service.CompleteMFA(ctx, step.ChallengeToken, localAuthPurposeAdmin, "", code)
	if err != nil || complete.Status != "complete" || len(complete.RecoveryCodes) != localMFARecoveryCodeCount {
		t.Fatalf("MFA completion=%#v err=%v", complete, err)
	}
	for _, recovery := range complete.RecoveryCodes {
		var raw int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM local_mfa_recovery_codes WHERE code_hash=?`, recovery).Scan(&raw); err != nil || raw != 0 {
			t.Fatalf("raw recovery code stored count=%d err=%v", raw, err)
		}
	}
	user, err := store.LocalUserByUsername(ctx, "alice")
	if err != nil || user.PasswordChangeRequired || !user.MFAEnabled || user.Revision != complete.Principal.LocalUserRevision {
		t.Fatalf("persisted user=%#v err=%v", user, err)
	}
}

func TestLocalMFARejectsTOTPReplayConsumesRecoveryAndResetInvalidatesTokens(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateLocalUser(ctx, LocalUser{Username: "alice", Subject: "alice-subject", Kind: humanIdentityKind,
		PasswordHash: mustPasswordHash(t, "permanent-password"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE local_users SET password_change_required=0 WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	cfg := AuthenticationConfig{TokenPepper: testPasswordPepper}
	passwords, _ := newLocalPasswordAuthenticator(ctx, cfg, store)
	service, err := newLocalAuthenticationService(cfg, store, passwords)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	principal, _ := passwords.Authenticate(ctx, "alice", "permanent-password")
	enroll, err := service.Begin(ctx, principal, localAuthPurposeOAuth, "client-binding")
	if err != nil {
		t.Fatal(err)
	}
	firstCode, _ := totp.GenerateCode(enroll.Secret, now)
	complete, err := service.CompleteMFA(ctx, enroll.ChallengeToken, localAuthPurposeOAuth, "client-binding", firstCode)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(30 * time.Second)
	principal, _ = passwords.Authenticate(ctx, "alice", "permanent-password")
	challenge, _ := service.Begin(ctx, principal, localAuthPurposeOAuth, "client-binding")
	secondCode, _ := totp.GenerateCode(enroll.Secret, now)
	if _, err := service.CompleteMFA(ctx, challenge.ChallengeToken, localAuthPurposeOAuth, "wrong-binding", secondCode); !errors.Is(err, ErrLocalChallengeInvalid) {
		t.Fatalf("challenge crossed binding boundary: %v", err)
	}
	if _, err := service.CompleteMFA(ctx, challenge.ChallengeToken, localAuthPurposeOAuth, "client-binding", secondCode); err != nil {
		t.Fatalf("valid TOTP failed: %v", err)
	}
	replay, _ := service.Begin(ctx, principal, localAuthPurposeOAuth, "client-binding")
	if _, err := service.CompleteMFA(ctx, replay.ChallengeToken, localAuthPurposeOAuth, "client-binding", secondCode); !errors.Is(err, ErrLocalMFACodeInvalid) {
		t.Fatalf("TOTP replay error=%v", err)
	}
	recoveryChallenge, _ := service.Begin(ctx, principal, localAuthPurposeOAuth, "client-binding")
	if _, err := service.CompleteMFA(ctx, recoveryChallenge.ChallengeToken, localAuthPurposeOAuth, "client-binding", complete.RecoveryCodes[0]); err != nil {
		t.Fatalf("recovery code failed: %v", err)
	}
	reusedRecovery, _ := service.Begin(ctx, principal, localAuthPurposeOAuth, "client-binding")
	if _, err := service.CompleteMFA(ctx, reusedRecovery.ChallengeToken, localAuthPurposeOAuth, "client-binding", complete.RecoveryCodes[0]); !errors.Is(err, ErrLocalMFACodeInvalid) {
		t.Fatalf("reused recovery code error=%v", err)
	}

	user, _ := store.LocalUserByUsername(ctx, "alice")
	grant := LocalTokenGrant{Subject: user.Subject, LocalUserRevision: user.Revision, ClientID: "graphit-cli", Audience: "graphit-broker",
		Scopes: []string{localAPIScope}, FamilyID: "family", ExpiresAt: now.Add(time.Hour)}
	if err := store.SaveTokenPair(ctx, localAccessTokenPrefix+"before-reset", "before-reset", "", "", grant); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetLocalMFA(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	user, _ = store.LocalUserByUsername(ctx, "alice")
	if user.MFAEnabled || user.Revision == grant.LocalUserRevision {
		t.Fatalf("MFA reset user=%#v", user)
	}
	if _, err := store.AuthenticateLocalToken(ctx, localAccessTokenPrefix+"before-reset", "graphit-broker", []string{localAPIScope}); err == nil {
		t.Fatal("token survived MFA reset")
	}
	principal, _ = passwords.Authenticate(ctx, "alice", "permanent-password")
	reenroll, err := service.Begin(ctx, principal, localAuthPurposeAdmin, "")
	if err != nil || reenroll.Status != localAuthStageEnroll || reenroll.Secret == enroll.Secret {
		t.Fatalf("MFA reenrollment=%#v err=%v", reenroll, err)
	}
}

func TestLocalAuthChallengesExpireAndMFALimiterIsIndependentFromPasswordSuccess(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateLocalUser(ctx, LocalUser{Username: "alice", Subject: "alice-subject", Kind: humanIdentityKind,
		PasswordHash: mustPasswordHash(t, "temporary-password"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	cfg := AuthenticationConfig{TokenPepper: testPasswordPepper}
	passwords, _ := newLocalPasswordAuthenticator(ctx, cfg, store)
	service, _ := newLocalAuthenticationService(cfg, store, passwords)
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	principal, _ := passwords.Authenticate(ctx, "alice", "temporary-password")
	challenge, _ := service.Begin(ctx, principal, localAuthPurposeAdmin, "")
	now = now.Add(service.config.ChallengeTTL + time.Second)
	if _, err := service.CompletePasswordChange(ctx, challenge.ChallengeToken, localAuthPurposeAdmin, "", "permanent-password"); !errors.Is(err, ErrLocalChallengeInvalid) {
		t.Fatalf("expired challenge error=%v", err)
	}

	for range service.mfaLimiter.config.MaxFailures {
		service.mfaLimiter.record("alice", false)
	}
	if _, err := passwords.Authenticate(ctx, "alice", "temporary-password"); err != nil {
		t.Fatalf("password success failed: %v", err)
	}
	if err := service.mfaLimiter.allow("alice"); !errors.Is(err, ErrAuthenticationRateLimited) {
		t.Fatalf("password success reset independent MFA limiter: %v", err)
	}
}

func TestAdministrativePasswordChangeFlagInvalidatesArtifactsAndCannotBeClearedByUpdate(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateLocalUser(ctx, LocalUser{Username: "alice", Subject: "alice-subject", Kind: humanIdentityKind,
		PasswordHash: mustPasswordHash(t, "permanent-password"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE local_users SET password_change_required=0 WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	user, _ := store.LocalUserByUsername(ctx, "alice")
	grant := LocalTokenGrant{Subject: user.Subject, LocalUserRevision: user.Revision, ClientID: "graphit-cli", Audience: "graphit-broker",
		Scopes: []string{localAPIScope}, FamilyID: "family", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.SaveTokenPair(ctx, localAccessTokenPrefix+"before-force", "before-force", "", "", grant); err != nil {
		t.Fatal(err)
	}
	user.PasswordChangeRequired = true
	if err := store.UpdateLocalUser(ctx, "alice", user); err != nil {
		t.Fatal(err)
	}
	user, _ = store.LocalUserByUsername(ctx, "alice")
	if !user.PasswordChangeRequired || user.Revision == grant.LocalUserRevision {
		t.Fatalf("forced password state=%#v", user)
	}
	if _, err := store.AuthenticateLocalToken(ctx, localAccessTokenPrefix+"before-force", "graphit-broker", []string{localAPIScope}); err == nil {
		t.Fatal("token survived forced password change")
	}
	user.PasswordChangeRequired = false
	if err := store.UpdateLocalUser(ctx, "alice", user); err != nil {
		t.Fatal(err)
	}
	user, _ = store.LocalUserByUsername(ctx, "alice")
	if !user.PasswordChangeRequired {
		t.Fatal("administrative update cleared password-change requirement")
	}
	cfg := AuthenticationConfig{TokenPepper: testPasswordPepper}
	passwords, _ := newLocalPasswordAuthenticator(ctx, cfg, store)
	service, _ := newLocalAuthenticationService(cfg, store, passwords)
	principal, _ := passwords.Authenticate(ctx, "alice", "permanent-password")
	step, err := service.Begin(ctx, principal, localAuthPurposeAdmin, "")
	if err != nil || step.Status != localAuthStagePassword {
		t.Fatalf("forced password login step=%#v err=%v", step, err)
	}
}
