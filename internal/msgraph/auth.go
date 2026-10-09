// Package msgraph is the small slice of Microsoft Graph devtools needs: an
// OAuth device-code login, a token that refreshes itself, and an authenticated
// POST. It is deliberately transport-only and knows nothing about presence.
//
// Three refresh rules are encoded here because getting any of them wrong
// surfaces as an indistinguishable invalid_grant:
//
//   - Never up-scope. Azure rejects a refresh asking for scopes beyond what
//     was consented, so the scope parameter is rebuilt from the token's own
//     scp claim rather than a hardcoded superset.
//   - The tenant is never "common" for a work account. It comes from the tid
//     claim, with "organizations" as the only safe fallback.
//   - The refresh token rotates. The new one must be persisted or the next
//     refresh fails.
package msgraph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultClientID is the Azure CLI public client. It needs no app
// registration and no secret, and is pre-consented in most tenants, which is
// why it works out of the box.
//
// It is also not devtools: using it presents this tool to your tenant as the
// Azure CLI. A tenant can revoke or policy-block it at any time, and some
// security teams watch for exactly this pattern. Register your own Entra app
// with delegated Presence.ReadWrite and pass --client-id when you can.
const DefaultClientID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

// PresenceScope is the delegated permission setUserPreferredPresence needs.
// Application permissions are not an option here: the app-only equivalent is
// Presence.ReadWrite.All, which is tenant-wide admin consent.
const PresenceScope = "https://graph.microsoft.com/Presence.ReadWrite"

// authHost is a var, not a const, so tests can point the OAuth endpoints at
// an httptest server without a network.
var authHost = "https://login.microsoftonline.com"

const (
	graphBase = "https://graph.microsoft.com/v1.0"

	// Refresh this far before expiry rather than waiting for a 401.
	refreshSkew = 5 * time.Minute
)

// Token is a stored delegated token plus everything needed to refresh it.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ClientID     string    `json:"client_id"`
	TenantID     string    `json:"tenant_id"`
	Scopes       []string  `json:"scopes"`
	Expiry       time.Time `json:"expiry"`
	Account      string    `json:"account,omitempty"`
	// UserID is the oid claim, which is exactly the {id} that Graph's
	// /users/{id}/presence routes want - so no /me lookup is needed.
	UserID string `json:"user_id,omitempty"`
}

// Expired reports whether the access token is gone or about to be.
func (t *Token) Expired() bool {
	return t.AccessToken == "" || time.Until(t.Expiry) <= refreshSkew
}

// Tenant returns the tenant to authenticate against. "common" fails for work
// accounts, so fall back to "organizations" rather than guessing.
func (t *Token) Tenant() string {
	if t.TenantID != "" {
		return t.TenantID
	}
	return "organizations"
}

// HasScope reports whether the token actually carries a permission, so a
// missing one can be named instead of surfacing later as a 403.
func (t *Token) HasScope(want string) bool {
	short := want
	if i := strings.LastIndex(want, "/"); i >= 0 {
		short = want[i+1:]
	}
	for _, s := range t.Scopes {
		if strings.EqualFold(s, want) || strings.EqualFold(s, short) {
			return true
		}
	}
	return false
}

// claims are the few JWT fields that matter. The access token's own claims are
// authoritative over the token response's expires_in/scope fields, because the
// claims are what Graph enforces.
type claims struct {
	Exp int64  `json:"exp"`
	Scp string `json:"scp"`
	Tid string `json:"tid"`
	Oid string `json:"oid"`
	UPN string `json:"upn"`
	PU  string `json:"preferred_username"`
}

// parseClaims decodes a JWT payload without verifying it. That is sound here:
// the token came from Azure over TLS and is only being read for routing
// information, never trusted for authorization.
func parseClaims(jwt string) (*claims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return &c, nil
}

// tokenResponse is the shape of an Azure token endpoint success.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// authError is the shape of an Azure token endpoint failure.
type authError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *authError) Error() string {
	if e.Description != "" {
		// Azure descriptions start with an AADSTS code worth keeping; the
		// rest is a wall of correlation ids.
		d := e.Description
		if i := strings.IndexByte(d, '\r'); i > 0 {
			d = d[:i]
		}
		if i := strings.IndexByte(d, '\n'); i > 0 {
			d = d[:i]
		}
		return fmt.Sprintf("%s: %s", e.Code, d)
	}
	return e.Code
}

// Is lets callers test for a specific Azure error code.
func (e *authError) Is(target error) bool {
	var other *authError
	if errors.As(target, &other) {
		return other.Code == e.Code
	}
	return false
}

// postForm sends a form-encoded request to an Azure endpoint and decodes
// either shape of response.
func postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var body json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("%s: decoding response: %w", resp.Status, err)
	}
	if resp.StatusCode >= 400 {
		var ae authError
		if err := json.Unmarshal(body, &ae); err != nil || ae.Code == "" {
			return fmt.Errorf("%s from %s", resp.Status, endpoint)
		}
		return &ae
	}
	return json.Unmarshal(body, out)
}

// tokenFrom builds a Token from a token response, preferring the access
// token's own claims over the response envelope.
func tokenFrom(tr tokenResponse, clientID string, prev *Token) (*Token, error) {
	t := &Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ClientID:     clientID,
		Expiry:       time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
	if tr.Scope != "" {
		t.Scopes = strings.Fields(tr.Scope)
	}
	// The refresh token rotates, but a response may omit it; keep the old one
	// rather than losing the grant.
	if t.RefreshToken == "" && prev != nil {
		t.RefreshToken = prev.RefreshToken
	}

	if c, err := parseClaims(tr.AccessToken); err == nil {
		if c.Exp > 0 {
			t.Expiry = time.Unix(c.Exp, 0)
		}
		if c.Scp != "" {
			t.Scopes = strings.Fields(c.Scp)
		}
		if c.Tid != "" {
			t.TenantID = c.Tid
		}
		if c.Oid != "" {
			t.UserID = c.Oid
		}
		switch {
		case c.UPN != "":
			t.Account = c.UPN
		case c.PU != "":
			t.Account = c.PU
		}
	}
	if t.TenantID == "" && prev != nil {
		t.TenantID = prev.TenantID
	}
	if t.Account == "" && prev != nil {
		t.Account = prev.Account
	}
	if t.UserID == "" && prev != nil {
		t.UserID = prev.UserID
	}
	return t, nil
}

// DeviceCode is a pending device-code login.
type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
	Message         string `json:"message"`
}

// StartDeviceCode begins a device-code login and returns the code the user
// must enter. Nothing is authenticated until they do.
func StartDeviceCode(ctx context.Context, clientID, tenant string, scopes []string) (*DeviceCode, error) {
	if clientID == "" {
		clientID = DefaultClientID
	}
	if tenant == "" {
		tenant = "organizations"
	}
	form := url.Values{
		"client_id": {clientID},
		"scope":     {strings.Join(append(scopes, "offline_access"), " ")},
	}
	var dc DeviceCode
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", authHost, tenant)
	if err := postForm(ctx, endpoint, form, &dc); err != nil {
		return nil, err
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	return &dc, nil
}

// PollDeviceCode blocks until the user completes the login, the code expires,
// or ctx is cancelled.
func PollDeviceCode(ctx context.Context, clientID, tenant string, dc *DeviceCode) (*Token, error) {
	if clientID == "" {
		clientID = DefaultClientID
	}
	if tenant == "" {
		tenant = "organizations"
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", authHost, tenant)
	form := url.Values{
		"client_id":   {clientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {dc.DeviceCode},
	}

	wait := time.Duration(dc.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		if time.Now().After(deadline) {
			return nil, errors.New("device code expired before login completed")
		}

		var tr tokenResponse
		err := postForm(ctx, endpoint, form, &tr)
		if err == nil {
			return tokenFrom(tr, clientID, nil)
		}

		var ae *authError
		if !errors.As(err, &ae) {
			return nil, err
		}
		switch ae.Code {
		case "authorization_pending":
			// The user has not finished yet; keep waiting.
		case "slow_down":
			// Azure asks for a longer interval and will keep erroring if ignored.
			wait += 5 * time.Second
		default:
			// authorization_declined, bad_verification_code, expired_token.
			return nil, err
		}
	}
}

// Refresh exchanges the refresh token for a new access token. The returned
// Token is a new value; persist it, because the refresh token has rotated.
func (t *Token) Refresh(ctx context.Context) (*Token, error) {
	if t.RefreshToken == "" {
		return nil, errors.New("no refresh token stored; run \"devtools teams auth login\"")
	}
	// Rebuild the scope from what this token actually has. Requesting more
	// than was consented is rejected, and a token can never be up-scoped into
	// a permission it did not already carry.
	scopes := append([]string{}, t.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{PresenceScope}
	}
	form := url.Values{
		"client_id":     {t.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
		"scope":         {strings.Join(append(scopes, "offline_access"), " ")},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", authHost, t.Tenant())

	var tr tokenResponse
	if err := postForm(ctx, endpoint, form, &tr); err != nil {
		return nil, err
	}
	return tokenFrom(tr, t.ClientID, t)
}
