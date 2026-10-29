// Package cleanroom holds the repository-hygiene test: this repository
// is published, standalone, and meant to be read and audited end to
// end, so no internal jargon, tracker references, or
// not-for-publication material may appear anywhere in the tree. The
// blocklist below fails the build if any of it ever creeps back in
// (through a copied comment, a generated file, an example).
package cleanroom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// banned patterns, matched case-insensitively against every file in
// the repository except .git, LICENSE, go.sum, and this package.
var banned = []string{
	// Product issue-tracker and internal design-doc references: the
	// rationale a reader needs lives in this repository (README,
	// docs/api-contract.md), not behind a private tracker.
	"issue #", "issues/", "github.com/zeroquarry/zeroquarry", "adr-0",

	// References to the platform's private source tree: this repo must
	// describe behavior, not import it.
	".py", "wizard", "_parse_auth", "has_credential_auth",
	"scan_identities", "cookie_paste", "list_git_credentials",
	"summarize_identities", "require_mcp_auth", "_ensure_session_loaded",
	"normalize_git_host", "identity_roles", "allow_ssh_git_credentials",
	"aud-mcp", "mcp_oauth_", "idp-keycloak", "setup_realm",

	// Internal architecture/topology language.
	"control plane", "control-plane", "directory-of-record",
	"data plane", "console-stored",

	// People and tenants: no names, no email domains.
	"eskibars", "bookingexperts",

	// The console word is reserved for browser devtools only, and we
	// don't use even that; product UI is "the web app".
	"console",
}

// allowed overrides: (file, substring) pairs where a banned pattern is
// legitimately part of this repository's own text. Keep this list
// empty unless a real false positive shows up, and justify each entry.
var allowed = map[string][]string{}

func TestNoInternalReferences(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "cleanroom":
				// cleanroom: this package's own source must name the
				// banned patterns to ban them.
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case name == "LICENSE", name == "go.sum",
			strings.HasSuffix(name, ".png"), strings.HasSuffix(name, ".jpg"):
			return nil
		case strings.HasSuffix(name, ".go"), strings.HasSuffix(name, ".md"),
			strings.HasSuffix(name, ".yml"), strings.HasSuffix(name, ".yaml"),
			strings.HasSuffix(name, ".rb"), name == "go.mod", name == ".gitignore":
		default:
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(raw), "\n") {
			lower := strings.ToLower(line)
			for _, pattern := range banned {
				if !strings.Contains(lower, pattern) {
					continue
				}
				if permitted(rel, lower) {
					continue
				}
				t.Errorf("%s:%d: banned pattern %q (keep this repository standalone):\n\t%s",
					rel, i+1, pattern, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func permitted(rel, line string) bool {
	for _, a := range allowed[rel] {
		if strings.Contains(line, a) {
			return true
		}
	}
	return false
}
