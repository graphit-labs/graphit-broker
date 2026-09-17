package broker

import (
	"context"
	"testing"
	"time"
)

// revocationFixture creates one grant and returns the store plus the raw tokens naming it.
func revocationFixture(t *testing.T, family string) (*ControlStore, *brokerOIDCStorage, LocalTokenGrant) {
	t.Helper()
	store, err := OpenControlStore(testDatabase(":memory:"), testPasswordPepper)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CreateLocalUser(context.Background(), LocalUser{Username: "alice", Subject: "alice-subject",
		Kind: humanIdentityKind, PasswordHash: mustPasswordHash(t, "alice-password!"), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	user, _ := store.LocalUserByUsername(context.Background(), "alice")
	grant := LocalTokenGrant{Subject: user.Subject, LocalUserRevision: user.Revision, ClientID: "graphit-cli",
		Audience: "graphit-broker", Scopes: []string{testFixtureScope}, FamilyID: family,
		ExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := store.SaveTokenPair(context.Background(),
		localAccessTokenPrefix+family+"-access", family+"-access-id",
		localRefreshTokenPrefix+family+"-refresh", family+"-refresh-id", grant); err != nil {
		t.Fatal(err)
	}
	return store, &brokerOIDCStorage{control: store}, grant
}

func TestRevokingARefreshTokenEndsTheWholeGrant(t *testing.T) {
	// The framework resolves a refresh token through GetRefreshTokenInfo and then calls
	// RevokeToken with whatever that returned, which for this storage is the family id.
	// Driving the two calls in that order is what makes this a regression test: revoking
	// by the raw token would pass even with the defect this covers.
	store, storage, _ := revocationFixture(t, "family-refresh")

	_, tokenID, err := storage.GetRefreshTokenInfo(context.Background(), "graphit-cli", localRefreshTokenPrefix+"family-refresh-refresh")
	if err != nil {
		t.Fatalf("GetRefreshTokenInfo failed: %v", err)
	}
	if tokenID != "family-refresh" {
		t.Fatalf("GetRefreshTokenInfo returned %q; the revocation path depends on it naming the family", tokenID)
	}
	if revokeErr := storage.RevokeToken(context.Background(), tokenID, "alice-subject", "graphit-cli"); revokeErr != nil {
		t.Fatalf("RevokeToken failed: %v", revokeErr)
	}

	if _, err := store.OIDCRefreshTokenGrant(context.Background(), localRefreshTokenPrefix+"family-refresh-refresh"); err == nil {
		t.Error("the revoked refresh token can still be exchanged, so the grant did not end")
	}
	if _, err := store.OIDCAccessTokenGrant(context.Background(), "family-refresh-access-id"); err == nil {
		t.Error("an access token from the revoked grant is still valid")
	}
}

func TestRevokingAnAccessTokenLeavesItsRefreshTokenAlone(t *testing.T) {
	// Ending the grant from an access token is only a MAY in RFC 7009 section 2.1. This
	// pins the narrower behaviour so the family-first ordering above cannot widen it by
	// accident: an access token id must not be mistaken for a family id.
	store, storage, _ := revocationFixture(t, "family-access")

	if revokeErr := storage.RevokeToken(context.Background(), "family-access-access-id", "alice-subject", "graphit-cli"); revokeErr != nil {
		t.Fatalf("RevokeToken failed: %v", revokeErr)
	}

	if _, err := store.OIDCAccessTokenGrant(context.Background(), "family-access-access-id"); err == nil {
		t.Error("the revoked access token is still valid")
	}
	if _, err := store.OIDCRefreshTokenGrant(context.Background(), localRefreshTokenPrefix+"family-access-refresh"); err != nil {
		t.Errorf("revoking an access token also ended its grant: %v", err)
	}
}

func TestRevokingAnUnresolvedRawRefreshTokenEndsTheGrant(t *testing.T) {
	// When GetRefreshTokenInfo cannot resolve the token the framework passes the raw value
	// through instead, so that branch has to end the grant too.
	store, storage, _ := revocationFixture(t, "family-raw")

	if revokeErr := storage.RevokeToken(context.Background(), localRefreshTokenPrefix+"family-raw-refresh", "", "graphit-cli"); revokeErr != nil {
		t.Fatalf("RevokeToken failed: %v", revokeErr)
	}

	if _, err := store.OIDCAccessTokenGrant(context.Background(), "family-raw-access-id"); err == nil {
		t.Error("an access token from the revoked grant is still valid")
	}
}

func TestRevokingAnUnknownIdentifierIsNotAnError(t *testing.T) {
	// RFC 7009 section 2.2 requires 200 for a token the server does not recognise, so the
	// storage must not turn an unknown identifier into a server error.
	_, storage, _ := revocationFixture(t, "family-unknown")

	if revokeErr := storage.RevokeToken(context.Background(), "nothing-matches-this", "", "graphit-cli"); revokeErr != nil {
		t.Fatalf("an unknown identifier produced an error: %v", revokeErr)
	}
}

// testFixtureScope is an arbitrary scope used as fixture data. The broker requires no scope of
// its own anywhere; this only exercises the store's optional required-scopes parameter and the
// scopes recorded alongside a grant.
const testFixtureScope = "example.scope"
