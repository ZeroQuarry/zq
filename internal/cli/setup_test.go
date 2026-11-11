package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ZeroQuarry/zq/internal/config"
)

// withFakeHome isolates the machine state `zq setup` looks at: a fresh
// HOME, an isolated zq config dir, no deployment overrides, and an
// empty PATH (so binaries on the developer's machine can't flip
// detection while tests run). Returns the fake home dir.
func withFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ZQ_CONFIG_DIR", t.TempDir())
	t.Setenv("ZQ_URL", "")
	t.Setenv("PATH", t.TempDir())
	return home
}

const handoffLine = "Now tell your agent: connect to ZeroQuarry and get me started."

func claudeJSONPath(home string) string { return filepath.Join(home, ".claude.json") }
func cursorMCPPath(home string) string  { return filepath.Join(home, ".cursor", "mcp.json") }
func codexTOMLPath(home string) string  { return filepath.Join(home, ".codex", "config.toml") }

// detectCursorFor makes Cursor detectable via its config directory.
func detectCursorFor(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSetupConfiguresDetectedClients(t *testing.T) {
	home := withFakeHome(t)
	detectCursorFor(t, home)
	writeInitial(t, claudeJSONPath(home),
		`{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "srv"]}}, "projects": {"x": 1}}`)

	out, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "claude-code: added") || !strings.Contains(out, "cursor: added") {
		t.Fatalf("stdout summary missing: %q", out)
	}
	if !strings.Contains(stderr, handoffLine) {
		t.Fatalf("handoff line missing: %s", stderr)
	}

	// Claude Code got the entry, merged into the existing document.
	doc := decodeJSONFile(t, claudeJSONPath(home))
	entry := doc["mcpServers"].(map[string]any)["zeroquarry"].(map[string]any)
	if entry["url"] != "https://mcp.zeroquarry.com/" || entry["type"] != "http" {
		t.Fatalf("claude-code entry: %v", entry)
	}
	if _, ok := doc["mcpServers"].(map[string]any)["filesystem"]; !ok {
		t.Fatal("unrelated server entry was dropped")
	}
	if _, ok := doc["projects"]; !ok {
		t.Fatal("unrelated top-level key was dropped")
	}

	// Cursor's config was created fresh.
	cursorDoc := decodeJSONFile(t, cursorMCPPath(home))
	if cursorDoc["mcpServers"].(map[string]any)["zeroquarry"].(map[string]any)["url"] != "https://mcp.zeroquarry.com/" {
		t.Fatalf("cursor entry: %v", cursorDoc)
	}

	// Backups exist for both pre-existing/first writes.
	if _, err := os.Stat(claudeJSONPath(home) + ".zq-backup"); err != nil {
		t.Fatalf("claude backup: %v", err)
	}
}

func TestSetupIdempotentSecondRun(t *testing.T) {
	home := withFakeHome(t)
	detectCursorFor(t, home)
	writeInitial(t, claudeJSONPath(home), `{"mcpServers": {}}`)

	if _, _, code := runCLI(t, []string{"setup"}, ""); code != 0 {
		t.Fatal("first run failed")
	}
	claudeAfterFirst := readFile(t, claudeJSONPath(home))
	cursorAfterFirst := readFile(t, cursorMCPPath(home))

	out, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "claude-code: unchanged") || !strings.Contains(out, "cursor: unchanged") {
		t.Fatalf("second run summary: %q", out)
	}
	if strings.Contains(stderr, "backed up") {
		t.Fatalf("second run created another backup: %s", stderr)
	}
	if readFile(t, claudeJSONPath(home)) != claudeAfterFirst ||
		readFile(t, cursorMCPPath(home)) != cursorAfterFirst {
		t.Fatal("second run changed files")
	}
}

func TestSetupPrintOnlyWritesNothing(t *testing.T) {
	home := withFakeHome(t)
	detectCursorFor(t, home)
	writeInitial(t, claudeJSONPath(home), `{"mcpServers": {}}`)

	out, stderr, code := runCLI(t, []string{"setup", "--print-only"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	// The snippets are on stdout, ready to paste.
	if !strings.Contains(out, "https://mcp.zeroquarry.com/") {
		t.Fatalf("snippets missing: %q", out)
	}
	if !strings.Contains(out, "Any other MCP client") || !strings.Contains(out, `"mcpServers"`) {
		t.Fatalf("generic snippet missing: %q", out)
	}
	if !strings.Contains(stderr, "Nothing was written") {
		t.Fatalf("print-only notice missing: %s", stderr)
	}
	// Nothing changed on disk.
	if readFile(t, claudeJSONPath(home)) != `{"mcpServers": {}}` {
		t.Fatal("claude config was written")
	}
	if _, err := os.Stat(cursorMCPPath(home)); !os.IsNotExist(err) {
		t.Fatal("cursor config was created")
	}
}

func TestSetupNoClientsDetected(t *testing.T) {
	withFakeHome(t)

	out, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, `"mcpServers"`) || !strings.Contains(out, "https://mcp.zeroquarry.com/") {
		t.Fatalf("generic snippet missing: %q", out)
	}
	if !strings.Contains(stderr, handoffLine) {
		t.Fatalf("handoff line missing: %s", stderr)
	}
}

func TestSetupClaudeDesktopGuidanceOnly(t *testing.T) {
	home := withFakeHome(t)
	// The desktop config dir is platform-specific (~/Library/Application
	// Support on macOS, ~/.config elsewhere); create both so the test is
	// GOOS-independent.
	for _, dir := range [][]string{
		{"Library", "Application Support", "Claude"},
		{".config", "Claude"},
	} {
		if err := os.MkdirAll(filepath.Join(append([]string{home}, dir...)...), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	out, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "claude-desktop: manual") {
		t.Fatalf("desktop summary missing: %q", out)
	}
	if !strings.Contains(stderr, "Add custom connector") {
		t.Fatalf("connector guidance missing: %s", stderr)
	}
	// Nothing was written anywhere: the only client was the manual one.
	if _, err := os.Stat(claudeJSONPath(home)); !os.IsNotExist(err) {
		t.Fatal("a manual client must never get a config write")
	}
}

func TestSetupPrintOnlyShowsManualGuidance(t *testing.T) {
	home := withFakeHome(t)
	// Same dual-path trick as above: make the desktop client detectable
	// on whichever platform the suite runs.
	var mkErr error
	for _, dir := range [][]string{
		{"Library", "Application Support", "Claude"},
		{".config", "Claude"},
	} {
		if err := os.MkdirAll(filepath.Join(append([]string{home}, dir...)...), 0o755); err != nil {
			mkErr = err
		}
	}
	if mkErr != nil {
		t.Fatal(mkErr)
	}

	out, stderr, code := runCLI(t, []string{"setup", "--print-only"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	// The preview must carry the manual step itself, not just point at
	// it — the cautious user is reading stdout.
	if !strings.Contains(out, "Add custom connector") || !strings.Contains(out, "https://mcp.zeroquarry.com/") {
		t.Fatalf("manual guidance missing from preview: %q", out)
	}
}

func TestSetupContinuesPastBrokenClientConfig(t *testing.T) {
	home := withFakeHome(t)
	detectCursorFor(t, home)
	writeInitial(t, cursorMCPPath(home), `{"mcpServers": {`) // corrupt
	writeInitial(t, claudeJSONPath(home), `{"mcpServers": {}}`)

	out, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (one client failed)", code)
	}
	// The healthy client was still configured.
	if !strings.Contains(out, "cursor: failed") {
		t.Fatalf("cursor failure not reported: %q", out)
	}
	if _, err := os.Stat(claudeJSONPath(home)); os.IsNotExist(err) {
		t.Fatal("claude-code should have been configured despite the cursor failure")
	}
	if !strings.Contains(stderr, "could not be configured") {
		t.Fatalf("failure summary missing: %s", stderr)
	}
}

func TestSetupSelfHostedGuard(t *testing.T) {
	// ZQ_URL pointing at a self-hosted deployment: plain setup must
	// refuse to guess the MCP endpoint...
	withFakeHome(t)
	t.Setenv("ZQ_URL", "https://zq.corp.example.com")
	_, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 1 || !strings.Contains(stderr, "--mcp-url") {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}

	// ...and --mcp-url must carry through to the written entries.
	home := t.TempDir()
	t.Setenv("HOME", home)
	detectCursorFor(t, home)
	out, _, code := runCLI(t, []string{"setup", "--mcp-url", "https://zq.corp.example.com/mcp"}, "")
	if code != 0 {
		t.Fatal("setup with --mcp-url failed")
	}
	doc := decodeJSONFile(t, cursorMCPPath(home))
	if doc["mcpServers"].(map[string]any)["zeroquarry"].(map[string]any)["url"] != "https://zq.corp.example.com/mcp" {
		t.Fatalf("entry: %v", doc)
	}
	if strings.Contains(out, "https://mcp.zeroquarry.com/") {
		t.Fatalf("hosted URL leaked into a self-hosted setup: %q", out)
	}
}

// --api is a documented common flag: setup accepts it and applies the
// same self-hosted guard, instead of dying with a bare flag error.
func TestSetupAPIFlagSelfHostedRequiresMCPURL(t *testing.T) {
	withFakeHome(t)
	_, stderr, code := runCLI(t, []string{"setup", "--api", "https://zq.corp.example.com"}, "")
	if code != 1 || !strings.Contains(stderr, "--mcp-url") {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("--api must be accepted: %s", stderr)
	}
}

// --api naming the hosted deployment (or --mcp-url alongside a
// self-hosted --api) proceeds normally; the MCP URL wins.
func TestSetupAPIFlagCombinations(t *testing.T) {
	// Hosted --api → hosted MCP URL.
	home := withFakeHome(t)
	detectCursorFor(t, home)
	if _, _, code := runCLI(t, []string{"setup", "--api", config.DefaultAPIBase}, ""); code != 0 {
		t.Fatal("hosted --api should proceed")
	}
	doc := decodeJSONFile(t, cursorMCPPath(home))
	if got := doc["mcpServers"].(map[string]any)["zeroquarry"].(map[string]any)["url"]; got != "https://mcp.zeroquarry.com/" {
		t.Fatalf("url: %v", got)
	}

	// Self-hosted --api + explicit --mcp-url → the MCP URL wins.
	home = withFakeHome(t)
	detectCursorFor(t, home)
	out, _, code := runCLI(t, []string{
		"setup", "--api", "https://zq.corp.example.com",
		"--mcp-url", "https://zq.corp.example.com/mcp",
	}, "")
	if code != 0 {
		t.Fatal("--api + --mcp-url should proceed")
	}
	doc = decodeJSONFile(t, cursorMCPPath(home))
	if got := doc["mcpServers"].(map[string]any)["zeroquarry"].(map[string]any)["url"]; got != "https://zq.corp.example.com/mcp" {
		t.Fatalf("url: %v", got)
	}
	if strings.Contains(out, "https://mcp.zeroquarry.com/") {
		t.Fatalf("hosted URL leaked: %q", out)
	}
}

func TestSetupSelfHostedGuardViaSavedSettings(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("ZQ_CONFIG_DIR", cfgDir)
	t.Setenv("ZQ_URL", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	settings := `{"api_base": "https://zq.corp.example.com"}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 1 || !strings.Contains(stderr, "--mcp-url") {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
}

func TestSetupInvalidMCPURL(t *testing.T) {
	withFakeHome(t)
	_, stderr, code := runCLI(t, []string{"setup", "--mcp-url", "mcp.zeroquarry.com"}, "")
	if code != 1 || !strings.Contains(stderr, "scheme") {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
}

func TestSetupRejectsPositionalArgs(t *testing.T) {
	withFakeHome(t)
	_, stderr, code := runCLI(t, []string{"setup", "claude-code"}, "")
	if code != 2 || !strings.Contains(stderr, "unexpected argument") {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
}

func TestSetupHelpExitsZero(t *testing.T) {
	withFakeHome(t)
	if _, _, code := runCLI(t, []string{"setup", "-h"}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, _, code := runCLI(t, []string{"setup", "--help"}, ""); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// A hand-registered stdio server is not the tool's entry: it must be
// left alone, and the user must be told why — "skipped" on its own
// leaves them unable to tell whether the server got registered.
func TestSetupSkippedEntryExplainsItself(t *testing.T) {
	home := withFakeHome(t)
	original := `{"mcpServers": {"zeroquarry": {"command": "zq", "args": ["mcp"]}}}`
	writeInitial(t, claudeJSONPath(home), original)

	out, stderr, code := runCLI(t, []string{"setup"}, "")
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(out, "claude-code: skipped") {
		t.Fatalf("stdout summary missing: %q", out)
	}
	if !strings.Contains(stderr, "no url") || !strings.Contains(stderr, "stdio") {
		t.Fatalf("the skip reason is missing: %s", stderr)
	}
	// The entry the tool does not own is untouched, byte for byte.
	if got := readFile(t, claudeJSONPath(home)); got != original {
		t.Fatalf("the stdio entry was rewritten: %s", got)
	}
}

// --- small helpers -------------------------------------------------------

// writeInitial seeds a config file (and its directory) with content.
func writeInitial(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decodeJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(readFile(t, path)), &doc); err != nil {
		t.Fatalf("%s is not valid JSON: %v", path, err)
	}
	return doc
}
