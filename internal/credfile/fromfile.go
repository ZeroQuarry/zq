// Package credfile parses the files `--from-file` accepts: the
// "user-selected file" import path. The user's hand picks the file;
// the CLI reads it once, in memory, and uploads it — it never writes
// credential material anywhere else and never modifies the file.
package credfile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ZeroQuarry/zq/internal/cookies"
	"github.com/ZeroQuarry/zq/internal/platform"
)

// ReadFile loads a file's contents for parsing. Exported so callers
// control when the bytes exist (and how loudly failures are reported).
func ReadFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return raw, nil
}

// IdentityAuth builds identity credential material from a file's
// contents. Three accepted shapes:
//
//  1. the full auth object ({"cookies": ..., "headers": ...,
//     "basic_auth": ..., "form_login": ...}) — the shape an agent or a
//     power user writes verbatim;
//  2. cookie material in any shape browsers and cookie tools export
//     (JSON export, Netscape file, DevTools TSV, k=v lines,
//     document.cookie string);
//  3. `Header: value` lines (curl -v / raw HTTP header dumps).
//
// A JSON object that carries any auth-object key is treated strictly
// as shape 1 (unknown keys are typos and fail loudly); otherwise a
// JSON object is a {name: value} cookie map. Anything else must
// parse structurally: this CLI's only destination for the material is
// the upload, so unrecognized text fails loudly instead of shipping a
// garbage credential that would sit undetected until a scan ran
// unauthenticated. An operator who really does want a raw string
// stored verbatim forces it with --kind cookies.
func IdentityAuth(raw []byte) (*platform.Auth, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return nil, fmt.Errorf("file is empty")
	}
	if text[0] == '{' || text[0] == '[' {
		if text[0] == '{' && hasAuthObjectKey(text) {
			return authFromJSON(text)
		}
		// JSON cookie export (a list, or a {name: value} map).
		if normalized, ok := cookies.NormalizeJSON(text); ok {
			return &platform.Auth{Cookies: normalized}, nil
		}
		return nil, fmt.Errorf(
			"the file is JSON but neither an auth object nor a cookie export — " +
				"expected {\"cookies\": ...} or [{\"name\": ..., \"value\": ...}]")
	}
	if pairs := headerPairs(text); pairs != nil {
		headers := map[string]string{}
		for _, kv := range pairs {
			headers[kv[0]] = kv[1]
		}
		return &platform.Auth{Headers: headers}, nil
	}
	if normalized, ok := cookies.Canonical(text); ok {
		return &platform.Auth{Cookies: normalized}, nil
	}
	return nil, fmt.Errorf(
		"could not recognize the file as an auth object, cookie material, or header lines — " +
			"if it really is a raw cookie string, re-run with --kind cookies to store it verbatim")
}

// hasAuthObjectKey reports whether a JSON object carries one of the
// platform auth object's keys.
func hasAuthObjectKey(text string) bool {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &keys); err != nil {
		return false
	}
	for k := range keys {
		switch k {
		case "cookies", "headers", "basic_auth", "form_login":
			return true
		}
	}
	return false
}

// IdentityAuthKinded is IdentityAuth with an explicit kind override.
// File kinds: "cookies" (store the text verbatim as the cookie
// string), "headers" (require `Name: value` lines), "auth" (require
// the full auth JSON object), or "" / "auto" (sniff).
func IdentityAuthKinded(raw []byte, kind string) (*platform.Auth, error) {
	switch kind {
	case "", "auto":
		return IdentityAuth(raw)
	case "auth":
		return authFromJSON(strings.TrimSpace(string(raw)))
	case "cookies":
		normalized := cookies.Normalize(string(raw))
		if normalized == "" {
			return nil, fmt.Errorf("no cookie material found in the file")
		}
		return &platform.Auth{Cookies: normalized}, nil
	case "headers":
		pairs := headerPairs(strings.TrimSpace(string(raw)))
		if pairs == nil {
			return nil, fmt.Errorf("no `Header: value` lines found in the file")
		}
		headers := map[string]string{}
		for _, kv := range pairs {
			headers[kv[0]] = kv[1]
		}
		return &platform.Auth{Headers: headers}, nil
	default:
		return nil, fmt.Errorf(
			"--kind %q does not apply to --from-file (file kinds: cookies, headers, auth) — "+
				"basic and form logins are interactive prompts; use an auth JSON object for files", kind)
	}
}

// authFromJSON parses the full auth object, rejecting unknown
// top-level keys so a typo'd file fails loudly instead of uploading a
// partial credential the platform would silently ignore (the accepted
// key set is exactly: cookies, headers, basic_auth, form_login).
func authFromJSON(text string) (*platform.Auth, error) {
	var a platform.Auth
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		return nil, err
	}
	var keys map[string]any
	if err := json.Unmarshal([]byte(text), &keys); err != nil {
		return nil, err
	}
	for k := range keys {
		switch k {
		case "cookies", "headers", "basic_auth", "form_login":
		default:
			return nil, fmt.Errorf("unknown auth key %q (allowed: cookies, headers, basic_auth, form_login)", k)
		}
	}
	if !a.HasCredential() {
		return nil, fmt.Errorf("the auth object carries no credential material")
	}
	return &a, nil
}

// headerPairs parses `Name: value` lines: plain header dumps (raw
// HTTP, `Header: value` extracts) and `curl -v` output. In curl -v
// output only the `> ` REQUEST lines carry credential material — the
// request/status line, response lines (`< `), informational lines
// (`* `), and send-data markers are skipped. Returns nil when the
// text doesn't look header-shaped: every kept line must split on the
// first colon into a token-only name.
func headerPairs(text string) [][2]string {
	var pairs [][2]string
	sawCurlVerb := false
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "* ") {
			// Blank lines, comments, and curl -v informational lines
			// (which appear before the first request line too).
			continue
		}
		if line == ">" || line == "<" || line == "{" || line == "}" {
			// curl's blank separators between the request, response,
			// and data blocks: real output ends these lines with CRLF,
			// so after trimming they are bare ">" / "<" — NOT the
			// "> " prefix the block detection below tests. Missing
			// one poisons the whole parse (any kept line without a
			// colon rejects the dump, and the text then falls through
			// to the cookie parser and ships as garbage).
			continue
		}
		if strings.HasPrefix(line, "> ") {
			// curl -v request line. The rest of the dump is noise, so
			// one of these switches the parser into curl mode.
			sawCurlVerb = true
			line = strings.TrimSpace(line[2:])
			if isHTTPLine(line) { // "POST /login HTTP/2" — not a header
				continue
			}
		} else if sawCurlVerb && (strings.HasPrefix(line, "< ") ||
			strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "{ ") ||
			strings.HasPrefix(line, "} ")) {
			// Response, informational, or transfer-progress line.
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil
		}
		name = strings.TrimSpace(name)
		if name == "" || !isToken(name) {
			return nil
		}
		pairs = append(pairs, [2]string{name, strings.TrimSpace(value)})
	}
	if len(pairs) == 0 {
		return nil
	}
	return pairs
}

var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "CONNECT": true, "OPTIONS": true, "TRACE": true,
}

// isHTTPLine reports whether a stripped curl -v line is the request
// line ("POST /login HTTP/2") or a status line ("HTTP/2 200") rather
// than a header. Method-aware on purpose: testing "last field starts
// with HTTP/" would also swallow a header whose VALUE starts with
// HTTP/ ("Upgrade: HTTP/2.0") — a silent credential drop.
func isHTTPLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	if strings.HasPrefix(fields[0], "HTTP/") {
		return true // status line
	}
	return httpMethods[fields[0]] && strings.HasPrefix(fields[len(fields)-1], "HTTP/")
}

// isToken matches RFC 9110 token chars for a header field name.
func isToken(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return len(s) > 0
}

// NormalizeGitHost reduces whatever the user pasted (a bare host, a
// URL, a host:port) to the bare hostname a git credential row stores.
// The port is dropped deliberately: the stored value exists so a scan
// can match credentials to clone URLs by host, and that matching is
// by bare hostname on both HTTPS and SSH (an scp-like clone URL
// git@gitlab.com:acme/web.git carries no port at all). An scp-like
// paste also loses its user@ prefix for the same reason — a stray
// "git@" would break the match.
func NormalizeGitHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if u, err := urlParse(host); err == nil {
			host = u
		}
	}
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.Trim(host, ".")
}

func urlParse(raw string) (string, error) {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return "", fmt.Errorf("no scheme")
	}
	rest := raw[schemeEnd+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", fmt.Errorf("no host")
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return strings.ToLower(rest), nil
}

// LooksLikePEM reports whether the bytes carry a PEM PRIVATE KEY
// marker (the ssh secret's sanity check before upload).
func LooksLikePEM(raw []byte) bool {
	return strings.Contains(string(raw), "-----BEGIN") && strings.Contains(string(raw), "PRIVATE KEY-----")
}
