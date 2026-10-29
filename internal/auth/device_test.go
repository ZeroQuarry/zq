package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ZeroQuarry/zq/internal/config"
)

// fakeDeployment is one httptest server playing all three roles in the
// discovery chain: the platform's RFC 9728 endpoint, the realm's OIDC
// metadata, and the realm's device/token endpoints.
type fakeDeployment struct {
	ts *httptest.Server

	deviceBodies   []string // responses the device endpoint serves, in order
	tokenBodies    []string // responses the token endpoint serves, in order
	tokenStatuses  []int
	deviceRequests []map[string]string
	tokenRequests  []map[string]string
}

func newFakeDeployment(t *testing.T, deviceBodies, tokenBodies []string, tokenStatuses []int) *fakeDeployment {
	t.Helper()
	f := &fakeDeployment{deviceBodies: deviceBodies, tokenBodies: tokenBodies, tokenStatuses: tokenStatuses}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ProtectedResource{
			Resource:             "https://api.example.com/api/v1/mcp",
			AuthorizationServers: []string{f.ts.URL + "/realms/zeroquarry"},
		})
	})
	mux.HandleFunc("/realms/zeroquarry/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OIDCMetadata{
			Issuer:                      f.ts.URL + "/realms/zeroquarry",
			DeviceAuthorizationEndpoint: f.ts.URL + "/realms/zeroquarry/device",
			TokenEndpoint:               f.ts.URL + "/realms/zeroquarry/token",
			RevocationEndpoint:          f.ts.URL + "/realms/zeroquarry/revoke",
		})
	})
	mux.HandleFunc("/realms/zeroquarry/device", func(w http.ResponseWriter, r *http.Request) {
		f.deviceRequests = append(f.deviceRequests, formOf(r))
		body := f.deviceBodies[0]
		f.deviceBodies = f.deviceBodies[1:]
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/realms/zeroquarry/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenRequests = append(f.tokenRequests, formOf(r))
		body := f.tokenBodies[0]
		f.tokenBodies = f.tokenBodies[1:]
		status := http.StatusOK
		if len(f.tokenStatuses) > 0 {
			status = f.tokenStatuses[0]
			f.tokenStatuses = f.tokenStatuses[1:]
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func formOf(r *http.Request) map[string]string {
	if err := r.ParseForm(); err != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range r.PostForm {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func (f *fakeDeployment) discover(t *testing.T) *Discovered {
	t.Helper()
	d, err := Discover(context.Background(), f.ts.Client(), f.ts.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return d
}

const deviceResponse = `{"device_code":"DC123","user_code":"ABCD-EFGH","verification_uri":"https://auth.example.com/device","verification_uri_complete":"https://auth.example.com/device?code=ABCD-EFGH","expires_in":600,"interval":0}`

func TestDeviceFlowHappyPath(t *testing.T) {
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	old := DefaultPollInterval
	DefaultPollInterval = 0
	t.Cleanup(func() { DefaultPollInterval = old })

	f := newFakeDeployment(t,
		[]string{deviceResponse},
		[]string{`{"access_token":"AT1","refresh_token":"RT1","token_type":"Bearer","expires_in":900}`},
		nil)
	d := f.discover(t)

	dc, err := StartDeviceFlow(context.Background(), f.ts.Client(), d)
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if dc.UserCode != "ABCD-EFGH" || dc.DeviceCode != "DC123" {
		t.Fatalf("unexpected device code response: %+v", dc)
	}
	// RFC 8707: the resource the platform advertises rides the
	// authorization request so the realm binds the token audience.
	if got := f.deviceRequests[0]["resource"]; got != "https://api.example.com/api/v1/mcp" {
		t.Errorf("authorization request resource = %q", got)
	}
	if got := f.deviceRequests[0]["client_id"]; got != ClientID {
		t.Errorf("client_id = %q", got)
	}

	tokens, err := PollForToken(context.Background(), f.ts.Client(), d, dc, nil)
	if err != nil {
		t.Fatalf("PollForToken: %v", err)
	}
	if tokens.AccessToken != "AT1" || tokens.RefreshToken != "RT1" {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
	if got := f.tokenRequests[0]["grant_type"]; got != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Errorf("grant_type = %q", got)
	}
}

func TestDeviceFlowPollStates(t *testing.T) {
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	old := DefaultPollInterval
	DefaultPollInterval = 0
	t.Cleanup(func() { DefaultPollInterval = old })

	t.Run("pending then success", func(t *testing.T) {
		f := newFakeDeployment(t,
			[]string{deviceResponse},
			[]string{
				`{"error":"authorization_pending"}`,
				`{"error":"slow_down"}`,
				`{"access_token":"AT","expires_in":300}`,
			},
			[]int{400, 400, 200})
		d := f.discover(t)
		dc, _ := StartDeviceFlow(context.Background(), f.ts.Client(), d)
		tokens, err := PollForToken(context.Background(), f.ts.Client(), d, dc, nil)
		if err != nil {
			t.Fatalf("PollForToken: %v", err)
		}
		if tokens.AccessToken != "AT" {
			t.Fatalf("token = %+v", tokens)
		}
		if len(f.tokenRequests) != 3 {
			t.Fatalf("expected 3 polls, got %d", len(f.tokenRequests))
		}
	})

	t.Run("access denied", func(t *testing.T) {
		f := newFakeDeployment(t,
			[]string{deviceResponse},
			[]string{`{"error":"access_denied"}`},
			[]int{400})
		d := f.discover(t)
		dc, _ := StartDeviceFlow(context.Background(), f.ts.Client(), d)
		if _, err := PollForToken(context.Background(), f.ts.Client(), d, dc, nil); err != ErrAccessDenied {
			t.Fatalf("want ErrAccessDenied, got %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := newFakeDeployment(t,
			[]string{`{"device_code":"DC","user_code":"U","verification_uri":"https://x","expires_in":1,"interval":0}`},
			[]string{`{"error":"expired_token"}`},
			[]int{400})
		d := f.discover(t)
		dc, _ := StartDeviceFlow(context.Background(), f.ts.Client(), d)
		_, err := PollForToken(context.Background(), f.ts.Client(), d, dc, nil)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want expiry error, got %v", err)
		}
	})
}

func TestDiscoverFailures(t *testing.T) {
	t.Run("no OAuth configured (404 on discovery)", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer ts.Close()
		_, err := Discover(context.Background(), ts.Client(), ts.URL)
		if err == nil || !strings.Contains(err.Error(), "ZQ_KEY") {
			t.Fatalf("want the static-key hint in the error, got %v", err)
		}
	})

	t.Run("realm without device flow", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(ProtectedResource{
				Resource:             "https://api.example.com/api/v1/mcp",
				AuthorizationServers: []string{"https://auth.example.com/realms/zeroquarry"},
			})
		})
		// The OIDC lookup hits auth.example.com — unreachable in tests,
		// which produces the "unreachable" error path.
		ts := httptest.NewServer(mux)
		defer ts.Close()
		_, err := Discover(context.Background(), ts.Client(), ts.URL)
		if err == nil {
			t.Fatal("want discovery to fail for an unreachable realm")
		}
	})
}

func TestRefreshGrant(t *testing.T) {
	f := newFakeDeployment(t, nil,
		[]string{`{"access_token":"AT2","refresh_token":"RT2","expires_in":900}`}, nil)
	d := f.discover(t)
	tokens, err := Refresh(context.Background(), f.ts.Client(), d, "RT1")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tokens.AccessToken != "AT2" || tokens.RefreshToken != "RT2" {
		t.Fatalf("unexpected refreshed tokens: %+v", tokens)
	}
	if got := f.tokenRequests[0]["grant_type"]; got != "refresh_token" {
		t.Errorf("grant_type = %q", got)
	}
	if got := f.tokenRequests[0]["refresh_token"]; got != "RT1" {
		t.Errorf("refresh_token = %q", got)
	}
}

func TestRevokeBestEffort(t *testing.T) {
	// Revoke never fails the command even when the endpoint is dead.
	f := newFakeDeployment(t, nil, nil, nil)
	d := f.discover(t)
	d.Revoke = f.ts.URL + "/nonexistent"
	Revoke(context.Background(), f.ts.Client(), d, "RT") // must not panic/error
	// And a missing endpoint is skipped entirely.
	Revoke(context.Background(), f.ts.Client(), &Discovered{}, "RT")
}

// bearer resolution -------------------------------------------------------

func TestBearerStaticKey(t *testing.T) {
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	t.Setenv("ZQ_KEY", "") // isolate
	b, err := Resolve(context.Background(), http.DefaultClient, "zq_static", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !b.Static || b.Token != "zq_static" {
		t.Fatalf("want static bearer, got %+v", b)
	}
}

func TestBearerNotLoggedIn(t *testing.T) {
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	if _, err := Resolve(context.Background(), http.DefaultClient, "", ""); err != ErrNotLoggedIn {
		t.Fatalf("want ErrNotLoggedIn, got %v", err)
	}
}

func TestBearerStoredTokenAndMismatch(t *testing.T) {
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	if err := config.SaveTokens(&config.Tokens{AccessToken: "AT-stored", APIBase: "https://api.example.com"}); err != nil {
		t.Fatal(err)
	}

	b, err := Resolve(context.Background(), http.DefaultClient, "", "https://api.example.com")
	if err != nil {
		t.Fatalf("Resolve same base: %v", err)
	}
	if b.Token != "AT-stored" {
		t.Fatalf("token = %q", b.Token)
	}

	// A token minted by one deployment must not be sent to another.
	_, err = Resolve(context.Background(), http.DefaultClient, "", "https://other.example.com")
	if err == nil || !strings.Contains(err.Error(), "zq login --api") {
		t.Fatalf("want cross-deployment guard, got %v", err)
	}

	// Host case differences are the SAME origin, not a mismatch.
	if _, err := Resolve(context.Background(), http.DefaultClient, "", "https://API.Example.COM"); err != nil {
		t.Fatalf("host case should not matter, got %v", err)
	}
}

func TestBearerProactiveRefresh(t *testing.T) {
	f := newFakeDeployment(t, nil,
		[]string{`{"access_token":"AT-new","refresh_token":"RT-new","expires_in":900}`}, nil)
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	// Expiry within the 60s refresh window triggers the pre-flight
	// refresh against the stored issuer.
	if err := config.SaveTokens(&config.Tokens{
		AccessToken: "AT-old", RefreshToken: "RT-old",
		Expiry: time.Now().Unix() + 10, Issuer: f.ts.URL + "/realms/zeroquarry", APIBase: f.ts.URL,
	}); err != nil {
		t.Fatal(err)
	}
	b, err := Resolve(context.Background(), f.ts.Client(), "", f.ts.URL)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if b.Token != "AT-new" || !b.Refreshed {
		t.Fatalf("want refreshed bearer, got %+v", b)
	}
	if err := b.Persist(); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	stored, err := config.LoadTokens()
	if err != nil || stored == nil {
		t.Fatalf("LoadTokens: %v", err)
	}
	if stored.AccessToken != "AT-new" {
		t.Fatalf("persisted token = %q", stored.AccessToken)
	}
}

// Ctrl-C must land during the poll wait, not after the current sleep.
func TestPollHonorsContextCancel(t *testing.T) {
	old := DefaultPollInterval
	DefaultPollInterval = 60 // a long wait the test must not sit through
	t.Cleanup(func() { DefaultPollInterval = old })

	f := newFakeDeployment(t,
		[]string{deviceResponse},
		[]string{`{"error":"authorization_pending"}`},
		[]int{400})
	d := f.discover(t)
	dc, _ := StartDeviceFlow(context.Background(), f.ts.Client(), d)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := PollForToken(ctx, f.ts.Client(), d, dc, nil)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // first poll fires, then waits
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt the poll wait")
	}
}
