package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ZeroQuarry/zq/internal/config"
)

// Bearer resolves the credentials every API call uses, in this order:
//
//  1. a static key passed explicitly (--token or ZQ_KEY) — the
//     indefinitely-supported CI/headless path, and
//  2. the stored device-flow token, proactively refreshed from the
//     stored issuer when it is within 60s of expiring.
//
// A nil Bearer means "not signed in": callers print the `zq login` hint.
type Bearer struct {
	Token string
	// Refreshed reports whether the stored token was rotated during
	// resolution (the caller may want to persist it).
	Refreshed bool
	// Static is true for flag/env keys (no expiry, no refresh).
	Static bool

	tokens *config.Tokens
}

// ErrNotLoggedIn marks the "no credentials anywhere" case.
var ErrNotLoggedIn = errors.New("not signed in")

// Resolve computes the bearer for an API call. apiBase picks the
// deployment the stored tokens were minted for (a mismatch is an
// error: a token minted by one deployment must not be sent to another).
func Resolve(ctx context.Context, client *http.Client, staticKey, apiBase string) (*Bearer, error) {
	if staticKey != "" {
		return &Bearer{Token: staticKey, Static: true}, nil
	}
	tokens, err := config.LoadTokens()
	if err != nil {
		return nil, err
	}
	if tokens == nil {
		return nil, ErrNotLoggedIn
	}
	if apiBase != "" && tokens.APIBase != "" && !sameOrigin(apiBase, tokens.APIBase) {
		return nil, fmt.Errorf(
			"the stored login belongs to %s but this command targets %s — run `zq login --api %s`",
			tokens.APIBase, strings.TrimRight(apiBase, "/"), strings.TrimRight(apiBase, "/"))
	}

	b := &Bearer{Token: tokens.AccessToken, tokens: tokens}
	expiredSoon := tokens.Expiry == 0 || time.Now().Unix() >= tokens.Expiry-60
	if !expiredSoon || tokens.RefreshToken == "" || tokens.Issuer == "" {
		return b, nil
	}

	d, err := Discover(ctx, client, firstNonEmpty(tokens.APIBase, apiBase))
	if err != nil {
		// Discovery down but the token may still be valid server-side
		// (our 60s margin is conservative). Try it.
		return b, nil
	}
	fresh, err := Refresh(ctx, client, d, tokens.RefreshToken)
	if err != nil {
		// Same reasoning: let the API call decide (a 401 there carries
		// a better message than failing pre-emptively).
		return b, nil
	}
	b.Token = fresh.AccessToken
	b.Refreshed = true
	if fresh.RefreshToken != "" {
		b.tokens.RefreshToken = fresh.RefreshToken
	}
	b.tokens.AccessToken = fresh.AccessToken
	if fresh.ExpiresIn > 0 {
		b.tokens.Expiry = time.Now().Unix() + int64(fresh.ExpiresIn)
	}
	return b, nil
}

// Persist saves a refreshed token back to credentials.json.
func (b *Bearer) Persist() error {
	if !b.Refreshed || b.tokens == nil {
		return nil
	}
	return config.SaveTokens(b.tokens)
}

// Apply sets the Authorization header on an outgoing request.
func (b *Bearer) Apply(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+b.Token)
}

// sameOrigin compares scheme + host (case-insensitive): a stored
// login from https://API.example.com is the same deployment as
// https://api.example.com, and a path suffix on either side does not
// make them different deployments.
func sameOrigin(a, b string) bool {
	pa, errA := url.Parse(strings.TrimRight(a, "/"))
	pb, errB := url.Parse(strings.TrimRight(b, "/"))
	if errA != nil || errB != nil {
		return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
	}
	return strings.EqualFold(pa.Host, pb.Host) && pa.Scheme == pb.Scheme
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
