package platform

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	return &Client{Base: ts.URL, HTTP: ts.Client(), Auth: &fakeBearer{token: "tok"}}
}

type fakeBearer struct{ token string }

func (b *fakeBearer) Apply(r *http.Request) { r.Header.Set("Authorization", "Bearer "+b.token) }

func captured(w *map[string]any) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		*w = body
		_ = json.NewEncoder(rw).Encode(map[string]string{"id": "id-1234"})
	}
}

func TestAddIdentityPayloadShape(t *testing.T) {
	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(captured(&got)))
	defer ts.Close()

	c := testClient(t, ts)
	id, err := c.AddIdentity(context.Background(), "proj-1", "Session cookies", "primary", &Auth{
		Cookies: "session=SECRET",
		Headers: map[string]string{"X-API-Key": "SECRET2"},
	})
	if err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
	if id != "id-1234" {
		t.Fatalf("id = %q", id)
	}
	if got["label"] != "Session cookies" || got["role"] != "primary" {
		t.Fatalf("label/role wrong: %+v", got)
	}
	authMap, _ := got["auth"].(map[string]any)
	if authMap == nil {
		t.Fatalf("auth missing: %+v", got)
	}
	if authMap["cookies"] != "session=SECRET" {
		t.Fatalf("cookies wrong: %+v", authMap)
	}
	// Absent kinds must be OMITTED (Go zero values), not sent as
	// nulls/empties: key presence is how the server tells credential
	// kinds apart.
	if _, present := authMap["basic_auth"]; present {
		t.Fatalf("basic_auth should be absent: %+v", authMap)
	}
	if _, present := authMap["form_login"]; present {
		t.Fatalf("form_login should be absent: %+v", authMap)
	}
	// The upload path is POST to the project's identity library.
	// (method/path asserted in TestRequestLines.)
}

func TestAddGitPayloadShape(t *testing.T) {
	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(captured(&got)))
	defer ts.Close()

	id, err := testClient(t, ts).AddGitCredential(context.Background(),
		"corp gitlab", "ssh", "gitlab.com", "git", "PRIVATE KEY", "known hosts line")
	if err != nil {
		t.Fatalf("AddGitCredential: %v", err)
	}
	if id != "id-1234" {
		t.Fatalf("id = %q", id)
	}
	for k, want := range map[string]any{
		"name": "corp gitlab", "auth_type": "ssh", "host": "gitlab.com",
		"username": "git", "secret": "PRIVATE KEY", "known_hosts": "known hosts line",
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}

	// Without known_hosts the key is omitted (platform stores NULL).
	got = nil
	ts2 := httptest.NewServer(http.HandlerFunc(captured(&got)))
	defer ts2.Close()
	if _, err := testClient(t, ts2).AddGitCredential(context.Background(), "n", "https", "h", "u", "s", ""); err != nil {
		t.Fatal(err)
	}
	if _, present := got["known_hosts"]; present {
		t.Fatalf("known_hosts should be absent: %+v", got)
	}
}

func TestRequestLines(t *testing.T) {
	var method, path, authz, ctype string
	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		authz = r.Header.Get("Authorization")
		ctype = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_ = json.NewEncoder(rw).Encode(map[string]string{"id": "x"})
	}))
	defer ts.Close()

	if _, err := testClient(t, ts).AddIdentity(context.Background(), "P1", "l", "primary", &Auth{Cookies: "k=v"}); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/api/v1/projects/P1/identities" {
		t.Fatalf("wrong line: %s %s", method, path)
	}
	if authz != "Bearer tok" {
		t.Fatalf("Authorization = %q", authz)
	}
	if !strings.HasPrefix(ctype, "application/json") {
		t.Fatalf("Content-Type = %q", ctype)
	}
	if body["auth"].(map[string]any)["cookies"] != "k=v" {
		t.Fatalf("body = %+v", body)
	}
}

func TestErrorRendering(t *testing.T) {
	// The platform's JSON error text is quoted verbatim.
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte(`{"error": "SSH Git credentials are not available on your account tier"}`))
	}))
	defer ts.Close()
	_, err := testClient(t, ts).AddGitCredential(context.Background(), "n", "ssh", "h", "u", "s", "")
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "SSH Git credentials are not available on your account tier") {
		t.Fatalf("server error text lost: %v", err)
	}

	// 401 renders the status, never any request material.
	ts2 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts2.Close()
	_, err = testClient(t, ts2).AddIdentity(context.Background(), "p", "l", "primary", &Auth{Cookies: "SECRET=1"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want 401 error, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error message carries credential material: %v", err)
	}
}

func TestAuthHasCredential(t *testing.T) {
	if (&Auth{}).HasCredential() {
		t.Error("empty auth has no credential")
	}
	if !(&Auth{Cookies: "k=v"}).HasCredential() {
		t.Error("cookies count")
	}
	if !(&Auth{Headers: map[string]string{"A": "b"}}).HasCredential() {
		t.Error("headers count")
	}
	if !(&Auth{BasicAuth: &BasicAuth{Username: "u"}}).HasCredential() {
		t.Error("basic counts")
	}
	if !(&Auth{FormLogin: &FormLogin{URL: "https://x"}}).HasCredential() {
		t.Error("form login counts")
	}
	var nilAuth *Auth
	if nilAuth.HasCredential() {
		t.Error("nil auth has no credential")
	}
}

// A 401 must tell the user how to fix it, and a 403 what's missing —
// and neither may quote response bodies (a proxy or error page could
// echo the request, which is where credential values live).
func TestUnauthorizedAndForbiddenHints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte("<html>401. That's an error.</html>"))
	}))
	defer ts.Close()
	_, err := testClient(t, ts).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "zq login") {
		t.Fatalf("want the login hint, got %v", err)
	}

	ts2 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte(`{"error": "SSH Git credentials are not available on your account tier"}`))
	}))
	defer ts2.Close()
	_, err = testClient(t, ts2).AddGitCredential(context.Background(), "n", "ssh", "h", "u", "s", "")
	if err == nil || !strings.Contains(err.Error(), "does not have permission") {
		t.Fatalf("want the permission framing, got %v", err)
	}
	if !strings.Contains(err.Error(), "account tier") {
		t.Fatalf("server detail should be preserved: %v", err)
	}
}

// A nil bearer is an internal error, not a panic on the first request.
func TestNilBearerIsAnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	c := &Client{Base: ts.URL, HTTP: ts.Client()}
	if _, err := c.Whoami(context.Background()); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("want a clear error, got %v", err)
	}
}

// A 404 on the ingest routes (deployment without the API yet) names
// what's missing instead of a bare "not found".
func TestNotFoundGuidance(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.NotFound(rw, r) // Flask-style HTML 404, not JSON
	}))
	defer ts.Close()
	_, err := testClient(t, ts).Whoami(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not serve that endpoint") {
		t.Fatalf("want the 404 guidance, got %v", err)
	}
	if strings.Contains(err.Error(), "404 page not found") {
		t.Fatalf("raw body text leaked: %v", err)
	}
}
