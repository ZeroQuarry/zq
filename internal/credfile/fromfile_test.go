package credfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroQuarry/zq/internal/platform"
)

const pemKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
-----END PRIVATE KEY-----`

func TestIdentityAuthSniffing(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		check func(t *testing.T, a *platform.Auth)
	}{
		{
			"full auth object",
			`{"headers": {"Authorization": "Bearer tok"}, "cookies": "s=1"}`,
			func(t *testing.T, a *platform.Auth) {
				if a.Cookies != "s=1" || a.Headers["Authorization"] != "Bearer tok" {
					t.Fatalf("wrong auth: %+v", a)
				}
			},
		},
		{
			"cookie json export",
			`[{"name": "session", "value": "abc"}]`,
			func(t *testing.T, a *platform.Auth) {
				if a.Cookies != "session=abc" {
					t.Fatalf("want normalized cookies, got %q", a.Cookies)
				}
			},
		},
		{
			"cookie name=value lines",
			"session=abc\ntz=UTC",
			func(t *testing.T, a *platform.Auth) {
				if a.Cookies != "session=abc; tz=UTC" {
					t.Fatalf("want normalized cookies, got %q", a.Cookies)
				}
			},
		},
		{
			"header lines",
			"Authorization: Bearer tok\nX-API-Key: key123",
			func(t *testing.T, a *platform.Auth) {
				if a.Headers["Authorization"] != "Bearer tok" || a.Headers["X-API-Key"] != "key123" {
					t.Fatalf("want headers, got %+v", a.Headers)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := IdentityAuth([]byte(tc.in))
			if err != nil {
				t.Fatalf("IdentityAuth: %v", err)
			}
			tc.check(t, a)
		})
	}
}

func TestIdentityAuthRejects(t *testing.T) {
	cases := []string{
		`{"nonsense": true}`,             // unknown key, no auth key, no string values
		`{"cookies": "s=1", "wrong": 1}`, // auth object with a typo'd extra key
		`{}`,                             // no credential
		"",                               // empty
		`[{"nope": 1}]`,                  // JSON list with no cookie pairs
	}
	for _, in := range cases {
		if _, err := IdentityAuth([]byte(in)); err == nil {
			t.Errorf("IdentityAuth(%q) should have failed", in)
		}
	}
	// A JSON object with an auth key is parsed STRICTLY: a typo'd extra
	// key next to real material fails instead of uploading a partial
	// credential the platform would silently ignore.
	if _, err := IdentityAuthKinded([]byte(`{"cookies": "s=1", "wrong": 1}`), "auth"); err == nil {
		t.Error("strict auth parse should reject unknown keys")
	}
	// ...but a {name: value} object without auth keys is legitimate
	// cookie-map material (the platform's dict-export shape).
	if _, err := IdentityAuth([]byte(`{"session": "abc"}`)); err != nil {
		t.Errorf("cookie map should parse: %v", err)
	}
}

func TestIdentityAuthKinded(t *testing.T) {
	// An explicit kind override wins over sniffing.
	a, err := IdentityAuthKinded([]byte("Authorization: Bearer tok"), "headers")
	if err != nil {
		t.Fatalf("headers kind: %v", err)
	}
	if a.Headers["Authorization"] != "Bearer tok" {
		t.Fatalf("want headers, got %+v", a)
	}

	// cookies kind normalizes.
	a, err = IdentityAuthKinded([]byte("s=1"), "cookies")
	if err != nil {
		t.Fatalf("cookies kind: %v", err)
	}
	if a.Cookies != "s=1" {
		t.Fatalf("want cookies, got %+v", a)
	}

	// auth kind demands the full object.
	if _, err := IdentityAuthKinded([]byte("s=1"), "auth"); err == nil {
		t.Fatal("auth kind should reject a bare cookie line")
	}

	// unknown kind is a usage error.
	if _, err := IdentityAuthKinded([]byte("s=1"), "basic"); err == nil {
		t.Fatal("basic is not a file kind — should have failed")
	}
}

func TestHeaderVsCookieDisambiguation(t *testing.T) {
	// A k=v paste must NOT parse as headers: `=` isn't a colon split.
	if _, err := IdentityAuthKinded([]byte("session=abc"), "auto"); err != nil {
		t.Fatalf("cookie paste should sniff as cookies: %v", err)
	}
	a, _ := IdentityAuthKinded([]byte("session=abc"), "auto")
	if a.Cookies == "" || a.Headers != nil {
		t.Fatalf("want cookies not headers: %+v", a)
	}
}

func TestLooksLikePEM(t *testing.T) {
	if !LooksLikePEM([]byte(pemKey)) {
		t.Error("PEM not detected")
	}
	if LooksLikePEM([]byte("ghp_abcdef123")) {
		t.Error("token mistaken for PEM")
	}
	if LooksLikePEM([]byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("a certificate is not a private key")
	}
}

func TestNormalizeGitHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"github.com", "github.com"},
		{"  GitHub.COM  ", "github.com"},
		{"https://github.com/acme/api", "github.com"},
		{"https://git.corp.example.com:8443/acme/api", "git.corp.example.com"},
		{"git@gitlab.com:acme/web.git", "gitlab.com"},
		{"ssh://git@bitbucket.org/acme/web", "bitbucket.org"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := NormalizeGitHost(tc.in); got != tc.want {
			t.Errorf("NormalizeGitHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReadFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("empty file should fail")
	} else if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// curl -v output parses as REQUEST headers. The fixture below is the
// captured shape of real curl 8.7.1 output (CRLF on the wire lines,
// blank ">" / "<" separators, "*" info lines, "{ ...bytes data }"
// markers) — written from a live capture, NOT from memory, because
// the one line a from-memory fixture got wrong (the blank "> \r"
// separator) was exactly the line that broke the parse and shipped
// the whole dump as a garbage cookie string.
func TestCurlVerboseOutput(t *testing.T) {
	crlf := "\r\n"
	dump := "" +
		"* Uses proxy env variable no_proxy == '*'\n" +
		"*   Trying 127.0.0.1:18699...\n" +
		"* Connected to 127.0.0.1 (127.0.0.1) port 18699\n" +
		"> GET / HTTP/1.1" + crlf +
		"> Host: 127.0.0.1:18699" + crlf +
		"> Authorization: Bearer sekrit-token" + crlf +
		"> Upgrade: HTTP/2.0" + crlf +
		"> User-Agent: curl/8.7.1" + crlf +
		"> Accept: */*" + crlf +
		"> " + crlf +
		"* Request completely sent off\n" +
		"* HTTP 1.0, assume close after body\n" +
		"< HTTP/1.0 200 OK" + crlf +
		"< Server: SimpleHTTP/0.6 Python/3.9.6" + crlf +
		"< Set-Cookie: session=resp-cookie" + crlf +
		"< Content-type: text/html; charset=utf-8" + crlf +
		"< " + crlf +
		"{ [11306 bytes data]\n" +
		"* Closing connection\n"

	a, err := IdentityAuth([]byte(dump))
	if err != nil {
		t.Fatalf("real curl -v output should parse: %v", err)
	}
	if a.Cookies != "" {
		t.Fatalf("nothing from a curl dump may become cookies, got %q", a.Cookies)
	}
	if a.Headers == nil {
		t.Fatal("want request headers")
	}
	if a.Headers["Authorization"] != "Bearer sekrit-token" {
		t.Errorf("Authorization: %q", a.Headers["Authorization"])
	}
	// A header whose VALUE starts with HTTP/ must survive (the request
	// line is detected by method, not by "ends with HTTP/").
	if a.Headers["Upgrade"] != "HTTP/2.0" {
		t.Errorf("Upgrade: %q", a.Headers["Upgrade"])
	}
	for _, banned := range []string{"Set-Cookie", "Server", "Content-type"} {
		if _, ok := a.Headers[banned]; ok {
			t.Errorf("response header %q must not become request material", banned)
		}
	}
	if _, ok := a.Headers["GET / HTTP/1.1"]; ok {
		t.Error("the request line must not become a header")
	}
}

// Unrecognized plain text now fails loudly instead of being stored as
// a garbage cookie string; --kind cookies remains the explicit escape
// hatch that stores text verbatim.
func TestUnrecognizedInputFailsLoudly(t *testing.T) {
	if _, err := IdentityAuth([]byte("some odd paste 0x(custom)")); err == nil {
		t.Fatal("unrecognized input must fail, not ship as cookies")
	} else if !strings.Contains(err.Error(), "--kind cookies") {
		t.Fatalf("error should name the escape hatch: %v", err)
	}
	// The explicit override still stores verbatim.
	a, err := IdentityAuthKinded([]byte("some odd paste 0x(custom)"), "cookies")
	if err != nil {
		t.Fatalf("--kind cookies override: %v", err)
	}
	if a.Cookies != "some odd paste 0x(custom)" {
		t.Fatalf("verbatim storage broken: %q", a.Cookies)
	}
}

// The port is dropped on purpose: scan-time credential matching is by
// bare hostname (an scp-like clone URL carries no port), so storing
// "git.corp:2222" would orphan the credential it describes.
func TestNormalizeGitHostDropsPort(t *testing.T) {
	if got := NormalizeGitHost("git.corp.example.com:2222"); got != "git.corp.example.com" {
		t.Errorf("got %q", got)
	}
}
