// Package auth implements `zq login`: the OAuth 2.0 Device
// Authorization Grant (RFC 8628) against the deployment's OAuth
// stack.
//
// Discovery follows the same chain a spec-conforming MCP client uses:
//
//  1. GET {api}/.well-known/oauth-protected-resource   (RFC 9728)
//     → authorization_servers[0] is the Keycloak realm issuer
//  2. GET {issuer}/.well-known/openid-configuration
//     → device_authorization_endpoint + token_endpoint
//  3. The device grant, scoped openid email profile, requesting the
//     RFC 9728 `resource` value (RFC 8707) so the realm binds the
//     token's aud to the platform's pinned resource identifier.
//
// The CLI is a *public* client (`zq-cli`): no secret, PKCE-free by
// design of the device grant — the user's browser does the
// authenticating, the terminal only ever displays the user_code and
// never the tokens.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientID is this CLI's public client in the authorization-server
// realm; the deployment provisions it with the device grant enabled
// and the audience scope the platform's tokens carry (see
// docs/api-contract.md for the full server checklist).
const ClientID = "zq-cli"

// DefaultPollInterval is the polling cadence when the authorization
// server doesn't specify one (RFC 8628 §3.2 default is 5s); a var so
// tests run the flow instantly.
var DefaultPollInterval = 5

// Scopes requests the claims the platform's token→user join needs
// (it maps the verified email claim to the local account).
const Scopes = "openid email profile"

// ProtectedResource is the RFC 9728 discovery document.
type ProtectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// OIDCMetadata is the slice of the realm's discovery document the
// device flow needs.
type OIDCMetadata struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
}

// Discovered carries the resolved endpoints for one deployment.
type Discovered struct {
	Resource string
	Issuer   string
	Device   string // device_authorization_endpoint
	Token    string // token_endpoint
	Revoke   string // revocation_endpoint (optional)
}

// Discover walks the RFC 9728 → OIDC chain for the given API base.
func Discover(ctx context.Context, client *http.Client, apiBase string) (*Discovered, error) {
	apiBase = strings.TrimRight(apiBase, "/")
	pr, err := getJSON(ctx, client, apiBase+"/.well-known/oauth-protected-resource")
	if err != nil {
		return nil, fmt.Errorf(
			"this deployment does not advertise OAuth discovery (%w).\n"+
				"The deployment must publish RFC 9728 metadata (its OAuth resource-server wiring),\n"+
				"or use a static key instead: export ZQ_KEY=zq_...", err)
	}
	var resource ProtectedResource
	if err := json.Unmarshal(pr, &resource); err != nil {
		return nil, fmt.Errorf("unparseable RFC 9728 metadata from %s: %w", apiBase, err)
	}
	if len(resource.AuthorizationServers) == 0 {
		return nil, errors.New("RFC 9728 metadata lists no authorization server")
	}
	issuer := strings.TrimRight(resource.AuthorizationServers[0], "/")

	oidc, err := getJSON(ctx, client, issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("authorization server %s unreachable: %w", issuer, err)
	}
	var meta OIDCMetadata
	if err := json.Unmarshal(oidc, &meta); err != nil {
		return nil, fmt.Errorf("unparseable OIDC metadata from %s: %w", issuer, err)
	}
	if meta.DeviceAuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf(
			"realm %s does not advertise device flow (device_authorization_endpoint missing);\n"+
				"the zq-cli client needs the OAuth 2.0 Device Authorization Grant enabled (docs/api-contract.md)", issuer)
	}
	return &Discovered{
		Resource: resource.Resource,
		Issuer:   issuer,
		Device:   meta.DeviceAuthorizationEndpoint,
		Token:    meta.TokenEndpoint,
		Revoke:   meta.RevocationEndpoint,
	}, nil
}

// DeviceCode is the authorization request's response (RFC 8628 §3.2).
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// StartDeviceFlow POSTs the authorization request.
func StartDeviceFlow(ctx context.Context, client *http.Client, d *Discovered) (*DeviceCode, error) {
	form := url.Values{
		"client_id": {ClientID},
		"scope":     {Scopes},
	}
	if d.Resource != "" {
		// RFC 8707: bind the token's audience to the resource the
		// platform advertises (the same value MCP clients request).
		form.Set("resource", d.Resource)
	}
	dc, err := postFormGetJSON(ctx, client, d.Device, form)
	if err != nil {
		return nil, fmt.Errorf("device authorization request failed: %w", err)
	}
	var out DeviceCode
	if err := json.Unmarshal(dc, &out); err != nil {
		return nil, fmt.Errorf("unparseable device authorization response: %w", err)
	}
	if out.DeviceCode == "" || out.VerificationURI == "" {
		return nil, errors.New("device authorization response missing device_code/verification_uri")
	}
	if out.ExpiresIn == 0 {
		out.ExpiresIn = 600
	}
	if out.Interval == 0 {
		out.Interval = DefaultPollInterval
	}
	return &out, nil
}

// Tokens is the grant response's token payload.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// ErrAccessDenied distinguishes the user saying no at the consent
// screen from transient poll states.
var ErrAccessDenied = errors.New("sign-in was denied")

// PollForToken polls the token endpoint until the user completes (or
// abandons) the browser sign-in. The first poll fires immediately
// (users are often faster than the interval); afterwards it waits
// `interval` between polls, honouring ctx cancellation so Ctrl-C
// lands instantly. onPoll, when non-nil, is called after each pending
// response (the CLI uses it to print a waiting dot).
func PollForToken(ctx context.Context, client *http.Client, d *Discovered, dc *DeviceCode, onPoll func(wait time.Duration)) (*Tokens, error) {
	interval := time.Duration(dc.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("the sign-in window expired — run `zq login` again")
		}
		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {ClientID},
			"device_code": {dc.DeviceCode},
		}
		if d.Resource != "" {
			form.Set("resource", d.Resource)
		}
		body, status, err := postForm(ctx, client, d.Token, form)
		if err != nil {
			return nil, fmt.Errorf("token request failed: %w", err)
		}
		var parsed struct {
			Tokens
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &parsed)
		switch parsed.Error {
		case "":
			if status != http.StatusOK {
				return nil, fmt.Errorf("token endpoint returned HTTP %d", status)
			}
			if parsed.AccessToken == "" {
				return nil, errors.New("token endpoint returned no access token")
			}
			return &parsed.Tokens, nil
		case "authorization_pending":
			if onPoll != nil {
				onPoll(interval)
			}
		case "slow_down":
			// RFC 8628 §3.5: bump the interval by 5 seconds.
			interval += 5 * time.Second
			if onPoll != nil {
				onPoll(interval)
			}
		case "expired_token":
			return nil, errors.New("the sign-in window expired — run `zq login` again")
		case "access_denied":
			return nil, ErrAccessDenied
		default:
			// Any other named error is terminal: the server refused
			// the grant itself (bad client, missing scope, …) and
			// waiting cannot change that.
			msg := parsed.Error
			if parsed.Description != "" {
				msg = fmt.Sprintf("%s: %s", parsed.Error, parsed.Description)
			}
			return nil, fmt.Errorf("sign-in refused: %s", msg)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// Refresh exchanges a refresh token (grant_type=refresh_token).
func Refresh(ctx context.Context, client *http.Client, d *Discovered, refreshToken string) (*Tokens, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ClientID},
		"refresh_token": {refreshToken},
	}
	if d.Resource != "" {
		form.Set("resource", d.Resource)
	}
	body, status, err := postForm(ctx, client, d.Token, form)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Tokens
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.AccessToken == "" {
		if status >= 400 {
			return nil, fmt.Errorf("token refresh failed (HTTP %d, %s) — run `zq login` again", status, parsed.Error)
		}
		return nil, errors.New("token refresh returned no access token — run `zq login` again")
	}
	return &parsed.Tokens, nil
}

// Revoke best-effort revokes the refresh token at the realm's RFC 7009
// endpoint (logout hygiene). The real control stays with the platform,
// which re-checks the live account on every request — deactivating the
// user there ends access on the next call, no token ceremony needed.
func Revoke(ctx context.Context, client *http.Client, d *Discovered, refreshToken string) {
	if d == nil || d.Revoke == "" || refreshToken == "" {
		return
	}
	form := url.Values{
		"client_id":       {ClientID},
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}
	_, _, _ = postForm(ctx, client, d.Revoke, form)
}

// --- small HTTP helpers -------------------------------------------------

func getJSON(ctx context.Context, client *http.Client, url string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", url, resp.StatusCode)
	}
	return json.RawMessage(body), nil
}

func postFormGetJSON(ctx context.Context, client *http.Client, url string, form url.Values) (json.RawMessage, error) {
	body, status, err := postForm(ctx, client, url, form)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error != "" {
			return nil, fmt.Errorf("HTTP %d: %s", status, e.Error)
		}
		return nil, fmt.Errorf("HTTP %d", status)
	}
	return json.RawMessage(body), nil
}

// postForm POSTs a form and returns the (limited) body and status. It
// deliberately returns the body even on non-200: RFC 8628 polling
// errors ride 400s with JSON error fields.
func postForm(ctx context.Context, client *http.Client, url string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
