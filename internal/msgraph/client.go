package msgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// TokenPath is where the delegated token is stored, alongside the other state
// devtools keeps for itself.
//
// This is a 0600 file rather than the macOS keychain on purpose. Writing a
// secret with /usr/bin/security non-interactively requires passing it as an
// argv value, which is visible to ps for the lifetime of the call, and
// `security add-generic-password -w` with no value does not read stdin - it
// silently consumes the next flag as the password. A mode-0600 file in a
// mode-0700 directory leaks nothing through the process table and keeps this
// transport working on the linux builds, where Graph is just HTTPS.
func TokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "devtools", "msgraph", "token.json"), nil
}

// LoadToken reads the stored token. A missing file is reported as
// ErrNoToken so callers can tell "never logged in" from "unreadable".
var ErrNoToken = errors.New("no Microsoft Graph token stored")

// LoadToken reads and parses the token at path.
func LoadToken(path string) (*Token, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoToken
	}
	if err != nil {
		return nil, err
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &t, nil
}

// SaveToken writes the token with owner-only permissions, creating the
// directory the same way. The write is atomic so an interrupted save cannot
// leave a truncated token behind and destroy the grant.
func SaveToken(path string, t *Token) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".token-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// DeleteToken removes the stored token. A missing file is not an error.
func DeleteToken(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Client makes authenticated Graph calls, refreshing and re-persisting the
// token as needed.
type Client struct {
	Token *Token

	// path is where a refreshed token is written back. Empty means in-memory
	// only, which is what the tests use.
	path string

	// BaseURL is the Graph root; overridden in tests.
	BaseURL string

	HTTP *http.Client
}

// NewClient loads the stored token and returns a client for it.
func NewClient(path string) (*Client, error) {
	t, err := LoadToken(path)
	if err != nil {
		return nil, err
	}
	return &Client{Token: t, path: path, BaseURL: graphBase, HTTP: http.DefaultClient}, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return graphBase
}

// ensureFresh refreshes the access token when it is expired or close to it,
// persisting the result because the refresh token rotates on every use.
func (c *Client) ensureFresh(ctx context.Context) error {
	if c.Token == nil {
		return ErrNoToken
	}
	if !c.Token.Expired() {
		return nil
	}
	next, err := c.Token.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("refreshing Graph token: %w", err)
	}
	c.Token = next
	if c.path != "" {
		if err := SaveToken(c.path, next); err != nil {
			return fmt.Errorf("persisting refreshed token: %w", err)
		}
	}
	return nil
}

// UserPath builds a /users/{id} path for the signed-in user.
func (c *Client) UserPath(suffix string) (string, error) {
	if c.Token == nil || c.Token.UserID == "" {
		return "", errors.New("stored token carries no user id; run \"devtools teams auth login\" again")
	}
	return "/users/" + c.Token.UserID + "/" + strings.TrimPrefix(suffix, "/"), nil
}

// Post sends a JSON body to a Graph path. A nil body sends no content, which
// is what the clear-presence endpoints want.
func (c *Client) Post(ctx context.Context, path string, body any) error {
	if err := c.ensureFresh(ctx); err != nil {
		return err
	}

	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token.AccessToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return graphError(resp)
}

// graphError turns a Graph failure into something actionable. The common ones
// have specific causes worth naming rather than printing a bare status.
func graphError(resp *http.Response) error {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	_ = json.Unmarshal(raw, &payload)

	detail := payload.Error.Message
	if detail == "" {
		detail = strings.TrimSpace(string(raw))
	}
	if detail == "" {
		detail = resp.Status
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("Graph rejected the token (401): %s\n"+
			"the grant may have been revoked; run \"devtools teams auth login\" again", detail)
	case http.StatusForbidden:
		return fmt.Errorf("Graph refused the call (403): %s\n"+
			"this usually means the token lacks Presence.ReadWrite; it must be consented at login, "+
			"since Azure will not up-scope an existing grant", detail)
	default:
		return fmt.Errorf("Graph %s: %s", resp.Status, detail)
	}
}
