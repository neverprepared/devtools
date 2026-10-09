package msgraph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mintJWT builds an unsigned JWT with the given claims. Nothing verifies the
// signature, so a header and payload are enough to exercise claim parsing.
func mintJWT(t *testing.T, c map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

func TestParseClaimsPrefersTokenOverEnvelope(t *testing.T) {
	exp := time.Now().Add(90 * time.Minute).Unix()
	jwt := mintJWT(t, map[string]any{
		"exp": exp,
		"scp": "Presence.ReadWrite User.Read",
		"tid": "tenant-abc",
		"oid": "user-xyz",
		"upn": "someone@example.com",
	})

	// The envelope deliberately disagrees with the claims: a 60s expiry and a
	// single narrower scope. The claims are what Graph enforces, so they win.
	tok, err := tokenFrom(tokenResponse{
		AccessToken: jwt,
		ExpiresIn:   60,
		Scope:       "User.Read",
	}, "client-1", nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := tok.Expiry.Unix(); got != exp {
		t.Errorf("expiry: want the exp claim %d, got %d", exp, got)
	}
	if !tok.HasScope(PresenceScope) {
		t.Errorf("scopes should come from the scp claim, got %v", tok.Scopes)
	}
	if tok.TenantID != "tenant-abc" {
		t.Errorf("tenant: want tenant-abc, got %q", tok.TenantID)
	}
	if tok.UserID != "user-xyz" {
		t.Errorf("user id: want the oid claim, got %q", tok.UserID)
	}
	if tok.Account != "someone@example.com" {
		t.Errorf("account: want the upn claim, got %q", tok.Account)
	}
}

func TestTokenFromKeepsPreviousRefreshTokenWhenOmitted(t *testing.T) {
	prev := &Token{RefreshToken: "old-refresh", TenantID: "t1", UserID: "u1", Account: "a@b.c"}
	// A refresh response that omits refresh_token must not destroy the grant.
	tok, err := tokenFrom(tokenResponse{AccessToken: "not-a-jwt", ExpiresIn: 3600}, "c", prev)
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "old-refresh" {
		t.Errorf("refresh token should carry over, got %q", tok.RefreshToken)
	}
	for _, c := range []struct{ name, got, want string }{
		{"tenant", tok.TenantID, "t1"},
		{"user id", tok.UserID, "u1"},
		{"account", tok.Account, "a@b.c"},
	} {
		if c.got != c.want {
			t.Errorf("%s should carry over: want %q, got %q", c.name, c.want, c.got)
		}
	}
}

func TestHasScopeAcceptsShortAndFullForms(t *testing.T) {
	t.Run("short form from scp claim", func(t *testing.T) {
		tok := &Token{Scopes: []string{"Presence.ReadWrite"}}
		if !tok.HasScope(PresenceScope) {
			t.Error("a bare Presence.ReadWrite should satisfy the full URI form")
		}
	})
	t.Run("full URI form", func(t *testing.T) {
		tok := &Token{Scopes: []string{PresenceScope}}
		if !tok.HasScope(PresenceScope) {
			t.Error("the full URI form should match itself")
		}
	})
	t.Run("absent", func(t *testing.T) {
		tok := &Token{Scopes: []string{"User.Read"}}
		if tok.HasScope(PresenceScope) {
			t.Error("User.Read alone should not satisfy Presence.ReadWrite")
		}
	})
}

func TestTenantNeverFallsBackToCommon(t *testing.T) {
	// "common" fails for work accounts, so an unknown tenant must become
	// "organizations" rather than "common".
	if got := (&Token{}).Tenant(); got != "organizations" {
		t.Errorf("want organizations, got %q", got)
	}
	if got := (&Token{TenantID: "abc"}).Tenant(); got != "abc" {
		t.Errorf("want the tid claim, got %q", got)
	}
}

// TestRefreshDoesNotUpScope is the regression test for the rule that costs the
// most to rediscover: Azure rejects a refresh requesting scopes beyond what
// was consented, so the scope parameter must be rebuilt from the token's own
// scp claim and never from a hardcoded superset.
func TestRefreshDoesNotUpScope(t *testing.T) {
	var gotScope, gotTenant, gotGrant string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		gotScope = r.PostForm.Get("scope")
		gotGrant = r.PostForm.Get("grant_type")
		gotTenant = strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]

		jwt := mintJWT(t, map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"scp": "Presence.ReadWrite",
			"tid": "tenant-abc",
			"oid": "user-xyz",
		})
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:  jwt,
			RefreshToken: "rotated-refresh",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	old := authHost
	authHost = srv.URL
	defer func() { authHost = old }()

	tok := &Token{
		RefreshToken: "original-refresh",
		ClientID:     "client-1",
		TenantID:     "tenant-abc",
		// The grant only ever consented to this one scope.
		Scopes: []string{"Presence.ReadWrite"},
	}
	next, err := tok.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if gotGrant != "refresh_token" {
		t.Errorf("grant_type: want refresh_token, got %q", gotGrant)
	}
	if gotTenant != "tenant-abc" {
		t.Errorf("tenant should come from the token, got %q", gotTenant)
	}
	// Exactly the consented scope plus offline_access, nothing more.
	want := "Presence.ReadWrite offline_access"
	if gotScope != want {
		t.Errorf("refresh scope must not be up-scoped:\n want %q\n got  %q", want, gotScope)
	}
	if next.RefreshToken != "rotated-refresh" {
		t.Errorf("the rotated refresh token must be captured, got %q", next.RefreshToken)
	}
}

func TestRefreshWithoutRefreshTokenIsActionable(t *testing.T) {
	_, err := (&Token{}).Refresh(context.Background())
	if err == nil {
		t.Fatal("refreshing without a refresh token should error")
	}
	if !strings.Contains(err.Error(), "auth login") {
		t.Errorf("error should tell the user what to run, got: %v", err)
	}
}

func TestSaveTokenIsOwnerOnlyAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "token.json")
	in := &Token{
		AccessToken: "a", RefreshToken: "r", ClientID: "c",
		TenantID: "t", UserID: "u", Account: "x@y.z",
		Scopes: []string{"Presence.ReadWrite"},
		Expiry: time.Now().Add(time.Hour).Truncate(time.Second),
	}
	if err := SaveToken(path, in); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("a stored token must be owner-only: want 0600, got %#o", perm)
	}
	if di, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	} else if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("the token directory must be owner-only: want 0700, got %#o", perm)
	}

	out, err := LoadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.RefreshToken != in.RefreshToken || out.UserID != in.UserID || !out.HasScope(PresenceScope) {
		t.Errorf("token did not round-trip: %+v", out)
	}

	// No stray temp files from the atomic write.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("want only token.json left behind, got %d entries", len(entries))
	}
}

func TestLoadTokenMissingIsErrNoToken(t *testing.T) {
	_, err := LoadToken(filepath.Join(t.TempDir(), "absent.json"))
	if err != ErrNoToken {
		t.Errorf("want ErrNoToken, got %v", err)
	}
}

func TestDeleteTokenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	if err := DeleteToken(path); err != nil {
		t.Errorf("deleting a missing token should succeed, got %v", err)
	}
}

func TestClientRefreshesExpiredTokenAndPersistsRotation(t *testing.T) {
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwt := mintJWT(t, map[string]any{
			"exp": time.Now().Add(time.Hour).Unix(),
			"scp": "Presence.ReadWrite",
			"tid": "tenant-abc",
			"oid": "user-xyz",
		})
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: jwt, RefreshToken: "rotated", ExpiresIn: 3600,
		})
	}))
	defer authSrv.Close()
	old := authHost
	authHost = authSrv.URL
	defer func() { authHost = old }()

	var sawAuth string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer graphSrv.Close()

	path := filepath.Join(t.TempDir(), "token.json")
	if err := SaveToken(path, &Token{
		AccessToken: "stale", RefreshToken: "original", ClientID: "c",
		TenantID: "tenant-abc", UserID: "user-xyz",
		Scopes: []string{"Presence.ReadWrite"},
		Expiry: time.Now().Add(-time.Hour), // already expired
	}); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(path)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = graphSrv.URL

	p, err := c.UserPath("presence/setUserPreferredPresence")
	if err != nil {
		t.Fatal(err)
	}
	if p != "/users/user-xyz/presence/setUserPreferredPresence" {
		t.Errorf("unexpected user path: %s", p)
	}
	if err := c.Post(context.Background(), p, map[string]string{"availability": "Away"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sawAuth, "stale") || !strings.HasPrefix(sawAuth, "Bearer ") {
		t.Errorf("the request should carry the refreshed token, got %q", sawAuth)
	}

	// The rotation must survive on disk, or the next run cannot refresh.
	stored, err := LoadToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RefreshToken != "rotated" {
		t.Errorf("rotated refresh token was not persisted, got %q", stored.RefreshToken)
	}
}

func TestGraphErrorsAreActionable(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{http.StatusUnauthorized, "auth login"},
		{http.StatusForbidden, "Presence.ReadWrite"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"error":{"code":"x","message":"denied"}}`))
			}))
			defer srv.Close()

			c := &Client{
				Token:   &Token{AccessToken: "a", Expiry: time.Now().Add(time.Hour)},
				BaseURL: srv.URL,
			}
			err := c.Post(context.Background(), "/x", map[string]string{})
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestStartDeviceCodeSendsOfflineAccess(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://e","expires_in":900}`))
	}))
	defer srv.Close()
	old := authHost
	authHost = srv.URL
	defer func() { authHost = old }()

	dc, err := StartDeviceCode(context.Background(), "", "", []string{PresenceScope})
	if err != nil {
		t.Fatal(err)
	}
	// offline_access is what yields a refresh token; without it the login is
	// useless after an hour.
	if !strings.Contains(got.Get("scope"), "offline_access") {
		t.Errorf("scope must request offline_access, got %q", got.Get("scope"))
	}
	if got.Get("client_id") != DefaultClientID {
		t.Errorf("an empty client id should fall back to the default, got %q", got.Get("client_id"))
	}
	// A server that omits the poll interval must not produce a busy loop.
	if dc.Interval <= 0 {
		t.Errorf("interval should default to something positive, got %d", dc.Interval)
	}
}
