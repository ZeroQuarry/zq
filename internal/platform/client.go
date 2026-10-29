// Package platform is the API client for a ZeroQuarry deployment.
//
// The payload shapes are the platform's documented credential shapes:
//
//   - the identity `auth` object carries exactly one of: cookies (a
//     canonical `k=v; ...` string), headers (a name→value map),
//     basic_auth (username + password), or form_login (a login the
//     platform performs itself at scan start). The scan references the
//     stored material by id (auth_identity_id) and the platform
//     expands it where the scan runs — values never travel through the
//     agent that requested the scan;
//   - a git credential is (name, auth_type https|ssh, host, username,
//     secret, known_hosts), referenced by id as git_credential_id.
//
// The endpoints themselves are specified in docs/api-contract.md: the
// server-side half of this CLI.
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// BearerSource is what a client calls to authenticate a request.
// *auth.Bearer implements it; tests substitute fakes.
type BearerSource interface {
	Apply(req *http.Request)
}

// Client talks to one deployment with one bearer.
type Client struct {
	Base string // scheme://host, no trailing slash (paths here hardcode /api/v1)
	HTTP *http.Client
	Auth BearerSource
}

// New pins the base URL (defaulting to the hosted deployment).
func New(base string, bearer BearerSource) *Client {
	return &Client{
		Base: strings.TrimRight(base, "/"),
		HTTP: HTTP(),
		Auth: bearer,
	}
}

// HTTP is the shared API transport (separate from the OAuth client so
// tests can stub each independently).
func HTTP() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}

// APIError carries the platform's JSON error contract
// ({"error": "..."} with optional detail), so command output can quote
// the server's words instead of a bare status.
type APIError struct {
	Status int
	Method string
	Path   string
	Detail string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s %s failed with HTTP %d", e.Method, e.Path, e.Status)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// --- shared shapes ------------------------------------------------------

// Auth is the identity credential material. Exactly the keys the
// platform defines; values the model never sees.
type Auth struct {
	Cookies   string            `json:"cookies,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	BasicAuth *BasicAuth        `json:"basic_auth,omitempty"`
	FormLogin *FormLogin        `json:"form_login,omitempty"`
}

// BasicAuth is HTTP Basic material.
type BasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// FormLogin is a login the platform performs itself at scan start:
// a form POST (or JSON API login), plus — for API logins — where the
// response carries the session token and which header it becomes.
type FormLogin struct {
	URL           string            `json:"url"`
	UsernameField string            `json:"username_field,omitempty"`
	Username      string            `json:"username,omitempty"`
	PasswordField string            `json:"password_field,omitempty"`
	Password      string            `json:"password,omitempty"`
	ExtraFields   map[string]string `json:"extra_fields,omitempty"`
	Encoding      string            `json:"encoding,omitempty"` // "form" (default) | "json"
	TokenPath     string            `json:"token_path,omitempty"`
	TokenHeader   string            `json:"token_header,omitempty"`
}

// HasCredential reports whether the auth object carries at least one
// credential. The platform rejects uploads without one, so the CLI
// applies the same rule before sending.
func (a *Auth) HasCredential() bool {
	if a == nil {
		return false
	}
	return a.Cookies != "" || len(a.Headers) > 0 || a.BasicAuth != nil || a.FormLogin != nil
}

// IdentityRef is one row of the identity library — metadata only,
// never values: the list endpoint is defined to carry shapes and
// names, so there is nothing secret here to leak.
type IdentityRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Role  string `json:"role"`
	Kind  string `json:"auth_kind"`
}

// GitCredentialRef is one row of the account's git credentials —
// metadata only; the list endpoint never returns secret columns.
type GitCredentialRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	AuthType string `json:"auth_type"`
	Host     string `json:"host"`
	Username string `json:"username"`
}

// Project is the slice of the platform's project representation the
// CLI needs.
type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// --- endpoints ----------------------------------------------------------

// Whoami verifies the caller (GET /api/v1/whoami).
func (c *Client) Whoami(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/api/v1/whoami", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Projects lists the account's projects (GET /api/v1/projects).
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var out struct {
		Projects []Project `json:"projects"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/projects", nil, &out); err != nil {
		return nil, err
	}
	return out.Projects, nil
}

// AddIdentity uploads auth material to a project's identity library
// (POST /api/v1/projects/{id}/identities) and returns the reference id
// the agent uses as auth_identity_id.
func (c *Client) AddIdentity(ctx context.Context, projectID, label, role string, a *Auth) (string, error) {
	body := map[string]any{
		"label": label,
		"role":  role,
		"auth":  a,
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/projects/"+projectID+"/identities", body, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("platform accepted the identity but returned no id")
	}
	return out.ID, nil
}

// AddGitCredential uploads an HTTPS token or SSH key (POST
// /api/v1/git-credentials) and returns the reference id the agent uses
// as git_credential_id.
func (c *Client) AddGitCredential(ctx context.Context, name, authType, host, username, secret, knownHosts string) (string, error) {
	body := map[string]any{
		"name":      name,
		"auth_type": authType,
		"host":      host,
		"username":  username,
		"secret":    secret,
	}
	if knownHosts != "" {
		body["known_hosts"] = knownHosts
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/git-credentials", body, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("platform accepted the credential but returned no id")
	}
	return out.ID, nil
}

// IdentityRefs lists a project's identity library (metadata only).
func (c *Client) IdentityRefs(ctx context.Context, projectID string) ([]IdentityRef, error) {
	var out struct {
		Identities []IdentityRef `json:"identities"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/projects/"+projectID+"/identities", nil, &out); err != nil {
		return nil, err
	}
	return out.Identities, nil
}

// GitCredentialRefs lists the account's git credentials (metadata only).
func (c *Client) GitCredentialRefs(ctx context.Context) ([]GitCredentialRef, error) {
	var out struct {
		Credentials []GitCredentialRef `json:"credentials"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/git-credentials", nil, &out); err != nil {
		return nil, err
	}
	return out.Credentials, nil
}

// --- transport ----------------------------------------------------------

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.Auth == nil {
		return errors.New("no credentials configured for this client")
	}
	c.Auth.Apply(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return &APIError{Status: resp.StatusCode, Method: method, Path: path, Detail: errorDetail(resp, raw)}
	}
	if out == nil {
		return nil
	}
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s %s returned unparseable JSON: %w", method, path, err)
	}
	return nil
}

// errorDetail extracts the server's message without ever quoting the
// response body: the platform's JSON errors are operator-safe by
// contract, but a non-JSON body (a proxy error page, a stack trace)
// could echo the request back — and the request is the one place
// credential values exist on the wire. So: the JSON error text when
// the server sent one, canonical guidance for the auth statuses, and
// a bare status otherwise.
func errorDetail(resp *http.Response, raw []byte) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err == nil && parsed.Error != "" {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			// The server's "unauthorized" carries nothing actionable;
			// the fix is always the same.
			return "credential rejected — run `zq login`, or check ZQ_KEY if you use a static key"
		case http.StatusForbidden:
			return "the signed-in account does not have permission for this (" + parsed.Error + ")"
		}
		return parsed.Error
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return "credential rejected — run `zq login`, or check ZQ_KEY if you use a static key"
	case http.StatusForbidden:
		return "the signed-in account does not have permission for this"
	case http.StatusNotFound:
		return "this deployment does not serve that endpoint — it may not have the ingest API " +
			"enabled yet (see docs/api-contract.md)"
	}
	return http.StatusText(resp.StatusCode)
}
