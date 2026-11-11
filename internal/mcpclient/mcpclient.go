// Package mcpclient registers the ZeroQuarry MCP server with the MCP
// clients installed on this machine (Claude Code, Cursor, Codex, and —
// for anything else — a generic snippet the user merges by hand).
//
// This package edits config files a human owns, so it lives by four
// rules:
//
//   - Merge, never clobber. Only the "zeroquarry" entry is written;
//     unrelated servers, unknown keys, and user-added fields inside
//     the zeroquarry entry itself survive. A hand-registered entry
//     without a url (a stdio server, say) is left untouched. TOML
//     files are edited line-by-line, so comments and formatting
//     survive; JSON files are re-encoded (2-space indent, sorted
//     keys) with unrelated content and number precision preserved —
//     the original bytes live in the backup.
//   - Back up before the first write. The original bytes go to
//     <config>.zq-backup, and an existing backup is never overwritten,
//     so the true pre-zq original always survives re-runs.
//   - Idempotent. A second run with the same URL leaves the file
//     byte-for-byte unchanged (and creates no backup).
//   - Report exactly what happened: added, updated, unchanged, or
//     skipped — and what entry is now configured.
//
// There is no network access and no secret material here: everything
// is local file surgery that can run before any login exists.
package mcpclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ServerName is the key the MCP server is registered under in every
// client config.
const ServerName = "zeroquarry"

// DefaultServerURL is the hosted MCP endpoint. Self-hosted deployments
// pass their own endpoint instead (the CLI refuses to guess it).
const DefaultServerURL = "https://mcp.zeroquarry.com/"

// backupSuffix is appended to a config path for the pre-zq copy.
const backupSuffix = ".zq-backup"

// Kind is the config-file format a client uses.
type Kind int

const (
	KindJSON Kind = iota // mcpServers object in a .json file
	KindTOML             // [mcp_servers.<name>] table in a .toml file
)

// Status is what a merge did to a config file.
type Status string

const (
	StatusAdded     Status = "added"
	StatusUpdated   Status = "updated"
	StatusUnchanged Status = "unchanged"
	// StatusSkipped means an entry with our name already exists but is
	// not URL-shaped (a hand-rolled stdio server, say); the package
	// never overrides settings it does not recognize.
	StatusSkipped Status = "skipped"
)

// Result describes one merge.
type Result struct {
	Status Status
	// Backup is the backup file written for this change, if any. An
	// already-existing backup is never overwritten and not reported.
	Backup string
	// Entry is what is now configured: compact JSON for JSON clients,
	// the TOML table text for TOML clients.
	Entry string
}

// Client is one detected MCP client and how to configure it.
type Client struct {
	ID          string // stable, lowercase, used in output
	DisplayName string
	ConfigPath  string // the client's config file (may not exist yet)
	Kind        Kind
	// Entry builds the JSON server entry for this client (JSON clients
	// only). The url key is ours to keep correct; any shape the caller
	// wants beyond that belongs to the client.
	Entry func(serverURL string) map[string]any
	// Manual clients get printed guidance instead of a config write.
	ManualHint string
}

// Manual reports whether the client can only be configured by hand.
func (c Client) Manual() bool { return c.ManualHint != "" }

// Env is the environment detection reads. Tests build it explicitly;
// production code gets SystemEnv.
type Env struct {
	Home      string
	ConfigDir string // os.UserConfigDir() (XDG on linux, %AppData% on windows)
	AppData   string // windows %APPDATA%
	GOOS      string
	LookPath  func(string) (string, error)
}

// SystemEnv snapshots the real machine's environment.
func SystemEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("cannot locate the home directory: %w", err)
	}
	// UserConfigDir can fail (no HOME/XDG); detection degrades to ""
	// rather than refusing to run.
	configDir, _ := os.UserConfigDir()
	return Env{
		Home:      home,
		ConfigDir: configDir,
		AppData:   os.Getenv("APPDATA"),
		GOOS:      runtime.GOOS,
		LookPath:  exec.LookPath,
	}, nil
}

// Detect returns the MCP clients installed on this machine, in a
// stable order. A client counts as installed when its config directory
// or file exists, or its binary is on PATH — whichever signal exists.
func Detect(e Env) []Client {
	var out []Client

	// Claude Code: user-scope servers live in the top-level mcpServers
	// object of ~/.claude.json.
	claudeJSON := filepath.Join(e.Home, ".claude.json")
	if e.exists(claudeJSON) || e.exists(filepath.Join(e.Home, ".claude")) || e.onPath("claude") {
		out = append(out, Client{
			ID:          "claude-code",
			DisplayName: "Claude Code",
			ConfigPath:  claudeJSON,
			Kind:        KindJSON,
			Entry: func(url string) map[string]any {
				return map[string]any{"type": "http", "url": url}
			},
		})
	}

	// Cursor: global servers live in ~/.cursor/mcp.json.
	if e.exists(filepath.Join(e.Home, ".cursor")) || e.onPath("cursor") {
		out = append(out, Client{
			ID:          "cursor",
			DisplayName: "Cursor",
			ConfigPath:  filepath.Join(e.Home, ".cursor", "mcp.json"),
			Kind:        KindJSON,
			Entry: func(url string) map[string]any {
				return map[string]any{"url": url}
			},
		})
	}

	// Codex: servers are [mcp_servers.<name>] tables in config.toml.
	if e.exists(filepath.Join(e.Home, ".codex")) || e.onPath("codex") {
		out = append(out, Client{
			ID:          "codex",
			DisplayName: "Codex",
			ConfigPath:  filepath.Join(e.Home, ".codex", "config.toml"),
			Kind:        KindTOML,
		})
	}

	// Claude Desktop: its config file only takes local stdio servers —
	// remote servers are added through the app's custom connectors UI —
	// so it is detected and reported, never written to.
	if dir := e.desktopDir(); dir != "" && e.exists(dir) {
		out = append(out, Client{
			ID:          "claude-desktop",
			DisplayName: "Claude Desktop",
			ManualHint: "connects to remote servers through custom connectors — open " +
				"Claude Desktop Settings → Connectors → Add custom connector, then paste the URL",
		})
	}
	return out
}

// desktopDir is Claude Desktop's per-OS config directory ("" when it
// cannot be resolved on this platform).
func (e Env) desktopDir() string {
	switch e.GOOS {
	case "darwin":
		return filepath.Join(e.Home, "Library", "Application Support", "Claude")
	case "windows":
		if e.AppData != "" {
			return filepath.Join(e.AppData, "Claude")
		}
		if e.ConfigDir != "" {
			return filepath.Join(e.ConfigDir, "Claude")
		}
	default:
		if e.ConfigDir != "" {
			return filepath.Join(e.ConfigDir, "Claude")
		}
	}
	return ""
}

func (e Env) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (e Env) onPath(bin string) bool {
	if e.LookPath == nil {
		return false
	}
	_, err := e.LookPath(bin)
	return err == nil
}

// Merge registers the server at serverURL in this client's config,
// applying the merge/backup/idempotency rules of the package.
func (c Client) Merge(serverURL string) (Result, error) {
	switch {
	case c.Manual():
		return Result{}, errors.New("this client is configured by hand; there is nothing to merge")
	case c.Kind == KindTOML:
		return mergeTOML(c.ConfigPath, ServerName, serverURL)
	default:
		return mergeJSON(c.ConfigPath, ServerName, c.Entry(serverURL))
	}
}

// Snippet renders what would be added to this client's config — the
// cautious user's preview, and the copy-paste body for --print-only.
func (c Client) Snippet(serverURL string) string {
	if c.Manual() {
		return ""
	}
	if c.Kind == KindTOML {
		return fmt.Sprintf("[mcp_servers.%s]\nurl = %q\n", ServerName, serverURL)
	}
	return prettyJSON(c.Entry(serverURL))
}

// GenericSnippet is the plain MCP JSON for clients the package does
// not know by name (Windsurf, Zed, ...): merge it into the client's
// config under its "mcpServers" key.
func GenericSnippet(serverURL string) string {
	return prettyJSON(map[string]any{
		"mcpServers": map[string]any{
			ServerName: map[string]any{"url": serverURL},
		},
	})
}

// --- shared write helpers ------------------------------------------------

// backupOnce copies path to path+backupSuffix unless that backup
// already exists — the pre-zq original must never be overwritten by a
// later run. Returns the backup path and whether it was created now.
func backupOnce(path string) (string, bool, error) {
	dest := path + backupSuffix
	if _, err := os.Stat(dest); err == nil {
		return dest, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	perm := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.WriteFile(dest, raw, perm); err != nil {
		return "", false, err
	}
	return dest, true, nil
}

// writeFileAtomic writes via a temp file + rename so a crash mid-write
// can never leave a truncated client config behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".zq-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func modeFor(path string, exists bool) os.FileMode {
	if exists {
		if info, err := os.Stat(path); err == nil {
			return info.Mode().Perm()
		}
	}
	return 0o644
}

// encodeJSON marshals v without HTML escaping (config files hold URLs
// and shell args, not web text), with indent when pretty is true.
func encodeJSON(v any, pretty bool) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func prettyJSON(v any) string {
	s, err := encodeJSON(v, true)
	if err != nil {
		return ""
	}
	return s
}

// compactJSON is the one-line form used when reporting what was
// written.
func compactJSON(v any) string {
	s, err := encodeJSON(v, false)
	if err != nil {
		return ""
	}
	return strings.TrimRight(s, "\n")
}
