package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroQuarry/zq/internal/auth"
	"github.com/ZeroQuarry/zq/internal/config"
)

// fakePlatform is one httptest server that plays BOTH ends of the wire
// the CLI touches: the platform API (/api/v1/...) and — for `zq login`
// — the RFC 9728 discovery document pointing at the realm endpoints on
// the same server.
type fakePlatform struct {
	ts *httptest.Server

	// captured requests
	identityBodies []map[string]any
	gitBodies      []map[string]any
	authHeaders    []string
	tokenGrants    []string
	whoamiCalls    int

	tokenResponses []string // realm token endpoint responses, in order
	deviceResponse string
}

func newFakePlatform(t *testing.T) *fakePlatform {
	t.Helper()
	f := &fakePlatform{
		deviceResponse: `{"device_code":"DC","user_code":"WXYZ-KLMN","verification_uri":"https://auth.example.com/device","verification_uri_complete":"https://auth.example.com/device?code=WXYZ-KLMN","expires_in":600,"interval":0}`,
		tokenResponses: []string{`{"access_token":"AT","refresh_token":"RT","token_type":"Bearer","expires_in":3600}`},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://api.example.com/api/v1/mcp",
			"authorization_servers": []string{f.ts.URL + "/realms/zeroquarry"},
		})
	})
	mux.HandleFunc("/realms/zeroquarry/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                        f.ts.URL + "/realms/zeroquarry",
			"device_authorization_endpoint": f.ts.URL + "/realms/zeroquarry/device",
			"token_endpoint":                f.ts.URL + "/realms/zeroquarry/token",
			"revocation_endpoint":           f.ts.URL + "/realms/zeroquarry/revoke",
		})
	})
	mux.HandleFunc("/realms/zeroquarry/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(f.deviceResponse))
	})
	mux.HandleFunc("/realms/zeroquarry/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.tokenGrants = append(f.tokenGrants, r.PostForm.Get("grant_type"))
		body := f.tokenResponses[0]
		f.tokenResponses = f.tokenResponses[1:]
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/realms/zeroquarry/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/v1/whoami", func(w http.ResponseWriter, r *http.Request) {
		f.whoamiCalls++
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"account_id": "acc-1", "user_id": "u-1", "role": "owner"})
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"projects": []map[string]any{
				{"id": "proj-aaa", "name": "Main Site"},
				{"id": "proj-bbb", "name": "Internal API"},
			},
		})
	})
	mux.HandleFunc("/api/v1/projects/proj-aaa/identities", func(w http.ResponseWriter, r *http.Request) {
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		if r.Method == http.MethodPost {
			var body map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			f.identityBodies = append(f.identityBodies, body)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "ident-1234"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"identities": []map[string]any{
			{"id": "ident-1234", "label": "Session cookies", "role": "primary", "auth_kind": "cookies"},
		}})
	})
	mux.HandleFunc("/api/v1/projects/proj-bbb/identities", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		f.identityBodies = append(f.identityBodies, body)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "ident-5678"})
	})
	mux.HandleFunc("/api/v1/git-credentials", func(w http.ResponseWriter, r *http.Request) {
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		if r.Method == http.MethodPost {
			var body map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			f.gitBodies = append(f.gitBodies, body)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "gitcred-99"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"credentials": []map[string]any{
			{"id": "gitcred-99", "name": "corp (ssh)", "auth_type": "ssh", "host": "gitlab.com", "username": "git"},
		}})
	})

	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

// runCLI executes Main with the given piped stdin and returns
// (stdout, stderr, exit code).
func runCLI(t *testing.T, args []string, stdin string) (string, string, int) {
	t.Helper()
	var out, errBuf strings.Builder
	code := Main(context.Background(), args, strings.NewReader(stdin), &out, &errBuf)
	return out.String(), errBuf.String(), code
}

// withFakeEnv isolates config state and points the CLI at the fake.
// Auth defaults to a static test key (the fake accepts any bearer);
// tests that exercise the not-signed-in path clear ZQ_KEY themselves.
func withFakeEnv(t *testing.T, f *fakePlatform) {
	t.Helper()
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	t.Setenv("ZQ_URL", f.ts.URL)
	t.Setenv("ZQ_KEY", "zq_test_key")
	oldInterval := auth.DefaultPollInterval
	auth.DefaultPollInterval = 0
	t.Cleanup(func() { auth.DefaultPollInterval = oldInterval })
	oldOpen := openBrowserFn
	openBrowserFn = func(string) bool { return false }
	t.Cleanup(func() { openBrowserFn = oldOpen })
}

const secretPaste = "session=SUPERSECRET123; tz=UTC"

func TestCredsAddIdentityInteractive(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)

	// Piped stdin: the project menu answer (2 = Internal API), the
	// credential-kind menu answer (1 = cookies), then the paste.
	// Validation and project resolution run BEFORE the paste is read;
	// label prompting is skipped on a non-terminal stdin.
	out, stderr, code := runCLI(t, []string{"creds", "add", "identity"},
		"2\n1\n"+secretPaste+"\n")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}

	// THE output contract: stdout is the reference id and NOTHING else.
	if out != "ident-5678\n" {
		t.Fatalf("stdout must be exactly the id, got %q", out)
	}
	// The value never leaks to ANY output stream.
	if strings.Contains(out+stderr, "SUPERSECRET123") {
		t.Fatalf("secret leaked to output: %q / %q", out, stderr)
	}
	// The platform got the value over the authenticated upload.
	if len(f.identityBodies) != 1 {
		t.Fatalf("expected one upload, got %d", len(f.identityBodies))
	}
	body := f.identityBodies[0]
	if body["label"] != "Session cookies" || body["role"] != "primary" {
		t.Errorf("label/role: %+v", body)
	}
	// The paste was normalized to the canonical cookie string.
	if auth := body["auth"].(map[string]any); auth["cookies"] != secretPaste {
		t.Errorf("cookies: %v", auth["cookies"])
	}
	if !strings.Contains(f.authHeaders[0], "Bearer AT") && !strings.Contains(f.authHeaders[0], "zq_") {
		t.Errorf("upload was not authenticated: %q", f.authHeaders[0])
	}
}

func TestCredsAddIdentityFromJSONAuthFile(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)

	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(`{
		"form_login": {"url": "https://app.example.com/login", "username": "ops@example.com",
			"username_field": "email", "password": "FORMPASS", "password_field": "password",
			"encoding": "json", "token_path": "data.access_token"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	out, stderr, code := runCLI(t, []string{
		"creds", "add", "identity",
		"--project", "Main Site", // name → resolved to proj-aaa
		"--label", "App login", "--role", "victim",
		"--from-file", path,
	}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if out != "ident-1234\n" {
		t.Fatalf("stdout = %q", out)
	}
	if strings.Contains(out+stderr, "FORMPASS") {
		t.Fatal("secret leaked to output")
	}
	body := f.identityBodies[0]
	if body["label"] != "App login" || body["role"] != "victim" {
		t.Fatalf("label/role: %+v", body)
	}
	fl := body["auth"].(map[string]any)["form_login"].(map[string]any)
	if fl["url"] != "https://app.example.com/login" || fl["password"] != "FORMPASS" {
		t.Fatalf("form_login: %+v", fl)
	}
}

func TestCredsAddIdentityRejectsBadRoleWithoutUploading(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	path := filepath.Join(t.TempDir(), "c.txt")
	_ = os.WriteFile(path, []byte("session=x"), 0o600)

	out, stderr, code := runCLI(t, []string{
		"creds", "add", "identity", "--project", "Main Site", "--role", "superadmin", "--from-file", path,
	}, "")
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if out != "" {
		t.Fatalf("no id on failure, got %q", out)
	}
	if len(f.identityBodies) != 0 {
		t.Fatal("nothing should upload when validation fails")
	}
	if !strings.Contains(stderr, "invalid --role") {
		t.Fatalf("unhelpful error: %s", stderr)
	}
}

func TestCredsAddGitFromPEMFile(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)

	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	keyPath := filepath.Join(t.TempDir(), "deploy_key")
	if err := os.WriteFile(keyPath, []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}

	out, stderr, code := runCLI(t, []string{
		"creds", "add", "git",
		"--from-file", keyPath,
		"--host", "https://git.corp.example.com/acme/api",
		"--username", "git", "--name", "corp deploy key",
	}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if out != "gitcred-99\n" {
		t.Fatalf("stdout = %q", out)
	}
	if strings.Contains(out+stderr, "b3BlbnNzaC1rZXktdjEA") {
		t.Fatal("key material leaked to output")
	}
	body := f.gitBodies[0]
	// Type sniffed from the PEM; host normalized to the bare hostname.
	if body["auth_type"] != "ssh" {
		t.Fatalf("auth_type: %v", body["auth_type"])
	}
	if body["host"] != "git.corp.example.com" {
		t.Fatalf("host: %v", body["host"])
	}
	if body["secret"] != strings.TrimRight(pem, "\n") {
		t.Fatalf("secret: %v", body["secret"])
	}
}

func TestCredsAddGitInteractiveToken(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)

	// Menu: https; paste the token; host/username from flags; name
	// defaults without a prompt on non-terminal stdin.
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "git",
		"--host", "github.com", "--username", "x-oauth-basic",
	}, "1\nghp_TOKENVALUE99\n")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if out != "gitcred-99\n" {
		t.Fatalf("stdout = %q", out)
	}
	if strings.Contains(out+stderr, "ghp_TOKENVALUE99") {
		t.Fatal("token leaked to output")
	}
	body := f.gitBodies[0]
	if body["auth_type"] != "https" || body["secret"] != "ghp_TOKENVALUE99" {
		t.Fatalf("body: %+v", body)
	}
	if body["name"] != "github.com (https)" {
		t.Fatalf("default name: %v", body["name"])
	}
}

func TestCredsListNeverShowsValues(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)

	out, _, code := runCLI(t, []string{"creds", "list", "git"}, "")
	if code != 0 {
		t.Fatal("list git failed")
	}
	if !strings.Contains(out, "gitcred-99") || !strings.Contains(out, "gitlab.com") {
		t.Fatalf("references missing: %q", out)
	}

	out, _, code = runCLI(t, []string{"creds", "list", "identity", "--project", "Main Site"}, "")
	if code != 0 {
		t.Fatal("list identity failed")
	}
	if !strings.Contains(out, "ident-1234") {
		t.Fatalf("references missing: %q", out)
	}
	// The list surface carries metadata only; there is no value field
	// to leak by construction. Assert that.
	for _, line := range strings.Split(out, "\n") {
		for _, banned := range []string{"secret=", "password", "token="} {
			if strings.Contains(line, banned) {
				t.Errorf("list output carries suspicious material: %q", line)
			}
		}
	}
}

func TestWhoami(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	out, stderr, code := runCLI(t, []string{"whoami"}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "account_id: acc-1") || !strings.Contains(out, "user_id: u-1") {
		t.Fatalf("whoami out: %q", out)
	}
}

func TestLoginEndToEnd(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)

	out, stderr, code := runCLI(t, []string{"login"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	// The user code and URL are the ONLY things a login shows — and
	// tokens never appear anywhere.
	if !strings.Contains(stderr, "WXYZ-KLMN") || !strings.Contains(stderr, "auth.example.com/device") {
		t.Fatalf("login guidance missing: %s", stderr)
	}
	for _, stream := range []string{out, stderr} {
		if strings.Contains(stream, `"AT"`) || strings.Contains(stream, "refresh_token") {
			t.Fatalf("token material in output: %q", stream)
		}
	}
	// The realm saw the device grant, then the platform saw whoami.
	if len(f.tokenGrants) != 1 || f.tokenGrants[0] != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Fatalf("token grants: %v", f.tokenGrants)
	}
	if f.whoamiCalls != 1 {
		t.Fatalf("login must verify via whoami, calls: %d", f.whoamiCalls)
	}
	// Tokens stored for THIS deployment with tight permissions.
	tokens, err := config.LoadTokens()
	if err != nil || tokens == nil {
		t.Fatalf("tokens not stored: %v", err)
	}
	if tokens.AccessToken != "AT" || tokens.APIBase != f.ts.URL {
		t.Fatalf("stored tokens: %+v", tokens)
	}
	files, _ := config.Resolve()
	if info, err := os.Stat(files.Credentials); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file permissions: %v %v", info, err)
	}
	// The deployment is persisted for later invocations.
	settings, _ := config.LoadSettings()
	if settings.APIBase != f.ts.URL {
		t.Fatalf("settings: %+v", settings)
	}
}

func TestNotLoggedInHint(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	t.Setenv("ZQ_KEY", "") // the point of this test
	out, stderr, code := runCLI(t, []string{"creds", "add", "identity", "--project", "x"}, "")
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr, "zq login") || !strings.Contains(stderr, "ZQ_KEY") {
		t.Fatalf("hint missing: %s", stderr)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestServerErrorMessageQuotedNotSecret(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	// Point creds at a server that rejects the upload; the CLI must
	// relay the server's words and never the payload.
	path := filepath.Join(t.TempDir(), "c.txt")
	_ = os.WriteFile(path, []byte("session=TERRIBLESECRET"), 0o600)

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "Invalid role"}`))
	}))
	defer broken.Close()

	t.Setenv("ZQ_URL", broken.URL)
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "identity", "--project", "p", "--from-file", path,
	}, "")
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.Contains(stderr, "Invalid role") {
		t.Fatalf("server text missing: %s", stderr)
	}
	if strings.Contains(stderr, "TERRIBLESECRET") {
		t.Fatal("payload material leaked into the error path")
	}
}

func TestVersionCommand(t *testing.T) {
	out, _, code := runCLI(t, []string{"version"}, "")
	if code != 0 || !strings.HasPrefix(out, "zq ") {
		t.Fatalf("version: %q / %d", out, code)
	}
}

// --- review-driven regressions -------------------------------------------

// A typo'd --project must fail BEFORE the paste is read: an
// agent-facing piped run (empty stdin here) once prompted for the
// secret and only then reported the bad project.
func TestBadProjectFailsBeforeSecretPrompt(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "identity", "--project", "NO-SUCH", "--role", "primary",
	}, "")
	if code != 1 || out != "" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	if !strings.Contains(stderr, "no project matches") {
		t.Fatalf("error: %s", stderr)
	}
	if len(f.identityBodies) != 0 {
		t.Fatal("nothing should upload")
	}
}

// Same rule for git: a non-TTY run without --host fails before
// reading anything, so the piped secret can never be swallowed as the
// host (which would upload it as plaintext metadata).
func TestGitHostRequiredBeforeSecretPrompt(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	_, stderr, code := runCLI(t, []string{"creds", "add", "git"}, "")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr, "no --host given") {
		t.Fatalf("error: %s", stderr)
	}
	if len(f.gitBodies) != 0 {
		t.Fatal("nothing should upload")
	}
}

// The exact orphaning scenario from review round two: --type and
// --username given, the token on stdin, no --host. The token must not
// become the host (or anything else); the run fails with an upload
// count of zero.
func TestGitNoHostDoesNotAbsorbPipedSecret(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "git", "--type", "https", "--username", "git",
	}, "ghp_REALTOKEN\n")
	if code != 1 || out != "" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	if !strings.Contains(stderr, "no --host given") {
		t.Fatalf("error: %s", stderr)
	}
	if len(f.gitBodies) != 0 {
		t.Fatalf("uploaded: %+v", f.gitBodies)
	}
}

// An empty piped secret must fail the upload rather than store a
// credential with no material.
func TestGitEmptySecretFails(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "git", "--type", "https", "--host", "github.com", "--username", "git",
	}, "\n")
	if code != 1 || out != "" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	if !strings.Contains(stderr, "no credential material") {
		t.Fatalf("error: %s", stderr)
	}
	if len(f.gitBodies) != 0 {
		t.Fatalf("uploaded: %+v", f.gitBodies)
	}
}

// --kind basic/form are interactive kinds; a file must be told the
// right substitute instead of failing with a generic usage error.
func TestKindBasicFromFileExplains(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	path := filepath.Join(t.TempDir(), "c.txt")
	_ = os.WriteFile(path, []byte("user:pass"), 0o600)
	_, stderr, code := runCLI(t, []string{
		"creds", "add", "identity", "--project", "Main Site", "--kind", "basic", "--from-file", path,
	}, "")
	if code != 1 || !strings.Contains(stderr, "auth JSON object") {
		t.Fatalf("want guidance, got exit %d: %s", code, stderr)
	}
}

// --known-hosts with an HTTPS credential is a usage error, not a
// silent drop.
func TestKnownHostsWithHTTPSErrors(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	_ = os.WriteFile(kh, []byte("github.com ssh-ed25519 AAAA"), 0o600)
	tok := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(tok, []byte("ghp_x"), 0o600)
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "git", "--type", "https", "--host", "github.com",
		"--username", "x", "--from-file", tok, "--known-hosts", kh,
	}, "")
	if code != 1 || out != "" || !strings.Contains(stderr, "--known-hosts applies only to SSH") {
		t.Fatalf("exit %d, err: %s", code, stderr)
	}
	if len(f.gitBodies) != 0 {
		t.Fatal("nothing should upload")
	}
}

// -h is help, not a usage error: exit 0.
func TestHelpExitsZero(t *testing.T) {
	for _, args := range [][]string{
		{"login", "-h"},
		{"creds", "add", "identity", "--help"},
		{"whoami", "-h"},
	} {
		if _, _, code := runCLI(t, args, ""); code != 0 {
			t.Errorf("%v: exit %d, want 0", args, code)
		}
	}
}

// A corrupt credentials file must not trap the user in logout.
func TestLogoutWithCorruptFile(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	files, _ := config.Resolve()
	_ = os.WriteFile(files.Credentials, []byte("{corrupt"), 0o600)
	_, stderr, code := runCLI(t, []string{"logout"}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "unreadable") {
		t.Fatalf("stderr: %s", stderr)
	}
	if _, err := os.Stat(files.Credentials); !os.IsNotExist(err) {
		t.Fatal("corrupt file was not removed")
	}
}

// A scheme-less --api fails with a fix-it message, not a raw
// transport error.
func TestAPIFlagSchemeValidation(t *testing.T) {
	withFakeEnv(t, newFakePlatform(t))
	_, stderr, code := runCLI(t, []string{"whoami", "--api", "api.example.com"}, "")
	if code != 1 || !strings.Contains(stderr, "scheme") {
		t.Fatalf("exit %d, err: %s", code, stderr)
	}
}

// The end-to-end shape of the empty-credential finding: piped
// basic auth where the username and password are both empty lines.
// Must fail with no upload — an all-empty credential used to be
// stored with exit 0 and a reference id. (A username-only answer
// still uploads: the platform's own gate accepts it.)
func TestEmptyBasicAuthRejected(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	out, stderr, code := runCLI(t, []string{
		"creds", "add", "identity", "--project", "Main Site", "--kind", "basic", "--label", "x",
	}, "\n\n")
	if code != 1 || out != "" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	if !strings.Contains(stderr, "no credential material") {
		t.Fatalf("error: %s", stderr)
	}
	if len(f.identityBodies) != 0 {
		t.Fatalf("uploaded: %+v", f.identityBodies)
	}
}

// The --token flag is deliberately gone: a static API key must never
// ride the command line (shell history, process listings). The
// rejection is a usage error, and it must not echo the value.
func TestTokenFlagRemoved(t *testing.T) {
	f := newFakePlatform(t)
	withFakeEnv(t, f)
	t.Setenv("ZQ_KEY", "") // isolate: only the flag could authenticate here

	out, stderr, code := runCLI(t, []string{"whoami", "--token", "zq_SECRETVALUE"}, "")
	if code != 2 || out != "" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	if !strings.Contains(stderr, "-token") {
		t.Fatalf("expected the unknown-flag error: %s", stderr)
	}
	if strings.Contains(stderr, "zq_SECRETVALUE") {
		t.Fatal("the rejection echoed the secret value")
	}

	// The documented surface no longer advertises the flag either.
	help, _, hcode := runCLI(t, []string{"--help"}, "")
	if hcode != 0 {
		t.Fatalf("help exit %d", hcode)
	}
	if strings.Contains(help, "--token") {
		t.Fatal("usage text still advertises --token")
	}
}
