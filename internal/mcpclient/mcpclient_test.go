package mcpclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeEnv(t *testing.T, home string, bins ...string) Env {
	t.Helper()
	binDir := t.TempDir()
	for _, bin := range bins {
		if err := os.WriteFile(filepath.Join(binDir, bin), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Env{
		Home:      home,
		ConfigDir: filepath.Join(home, ".config"),
		GOOS:      "linux",
		LookPath: func(name string) (string, error) {
			for _, b := range bins {
				if b == name {
					return filepath.Join(binDir, name), nil
				}
			}
			return "", os.ErrNotExist
		},
	}
}

func ids(clients []Client) []string {
	out := make([]string, len(clients))
	for i, c := range clients {
		out[i] = c.ID
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestDetectAbsent(t *testing.T) {
	got := Detect(fakeEnv(t, t.TempDir()))
	if len(got) != 0 {
		t.Fatalf("expected nothing detected, got %v", ids(got))
	}
}

func TestDetectClaudeCodeByFileAndDir(t *testing.T) {
	home := t.TempDir()
	writeInitial(t, filepath.Join(home, ".claude.json"), "{}")
	got := Detect(fakeEnv(t, home))
	if !contains(ids(got), "claude-code") {
		t.Fatalf("claude-code not detected by config file: %v", ids(got))
	}

	home = t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	got = Detect(fakeEnv(t, home))
	if !contains(ids(got), "claude-code") {
		t.Fatalf("claude-code not detected by config dir: %v", ids(got))
	}
}

func TestDetectByBinaryOnPath(t *testing.T) {
	home := t.TempDir()
	got := Detect(fakeEnv(t, home, "claude", "cursor", "codex"))
	gotIDs := ids(got)
	for _, want := range []string{"claude-code", "cursor", "codex"} {
		if !contains(gotIDs, want) {
			t.Fatalf("%s not detected via binary: %v", want, gotIDs)
		}
	}
	// Config paths point at the files a merge would create.
	for _, c := range got {
		if c.Manual() {
			t.Fatalf("%s should not be manual", c.ID)
		}
		if !filepath.IsAbs(c.ConfigPath) {
			t.Fatalf("config path not absolute: %q", c.ConfigPath)
		}
	}
}

func TestDetectCursorAndCodexByDir(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{".cursor", ".codex"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := Detect(fakeEnv(t, home))
	gotIDs := ids(got)
	if !contains(gotIDs, "cursor") || !contains(gotIDs, "codex") {
		t.Fatalf("detection: %v", gotIDs)
	}
	for _, c := range got {
		if c.ID == "cursor" && filepath.Base(c.ConfigPath) != "mcp.json" {
			t.Fatalf("cursor config: %q", c.ConfigPath)
		}
		if c.ID == "codex" && filepath.Base(c.ConfigPath) != "config.toml" {
			t.Fatalf("codex config: %q", c.ConfigPath)
		}
	}
}

func TestDetectClaudeDesktop(t *testing.T) {
	home := t.TempDir()
	e := fakeEnv(t, home)
	// linux: ~/.config/Claude
	if err := os.MkdirAll(filepath.Join(e.ConfigDir, "Claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Detect(e)
	gotIDs := ids(got)
	if !contains(gotIDs, "claude-desktop") {
		t.Fatalf("claude-desktop not detected: %v", gotIDs)
	}
	var desktop Client
	for _, c := range got {
		if c.ID == "claude-desktop" {
			desktop = c
		}
	}
	if !desktop.Manual() {
		t.Fatal("claude-desktop must be manual (its config file only takes local servers)")
	}
	if desktop.ManualHint == "" {
		t.Fatal("manual client must carry guidance")
	}

	// darwin: ~/Library/Application Support/Claude
	home = t.TempDir()
	e = fakeEnv(t, home)
	e.GOOS = "darwin"
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !contains(ids(Detect(e)), "claude-desktop") {
		t.Fatal("claude-desktop not detected on darwin")
	}

	// No directory anywhere → not detected even with the other clients.
	home = t.TempDir()
	e = fakeEnv(t, home)
	if contains(ids(Detect(e)), "claude-desktop") {
		t.Fatal("claude-desktop detected without its directory")
	}
}

// Claude Desktop's documented Linux location is ~/.config/Claude, but
// Go's os.UserConfigDir() resolves to $XDG_CONFIG_HOME when that is
// set — so the home location has to be checked on its own, or a
// desktop with XDG pointed elsewhere is never detected.
func TestDetectClaudeDesktopOutsideXDG(t *testing.T) {
	home := t.TempDir()
	e := fakeEnv(t, home)
	// A config dir that points somewhere else entirely.
	e.ConfigDir = filepath.Join(t.TempDir(), "xdg")
	if err := os.MkdirAll(filepath.Join(home, ".config", "Claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Detect(e)
	if !contains(ids(got), "claude-desktop") {
		t.Fatalf("claude-desktop not detected via ~/.config: %v", ids(got))
	}
}

func TestDetectStableOrder(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{".cursor", ".codex", ".claude"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := fakeEnv(t, home)
	if err := os.MkdirAll(filepath.Join(e.ConfigDir, "Claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := "claude-code cursor codex claude-desktop"
	for range 5 {
		if got := strings.Join(ids(Detect(e)), " "); got != want {
			t.Fatalf("order drifted: %q", got)
		}
	}
}

func TestSnippets(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := fakeEnv(t, home)
	var cursor Client
	for _, c := range Detect(e) {
		if c.ID == "cursor" {
			cursor = c
		}
	}
	s := cursor.Snippet(testURL)
	var entry map[string]any
	if err := json.Unmarshal([]byte(s), &entry); err != nil {
		t.Fatalf("json snippet not valid JSON: %v\n%s", err, s)
	}
	if entry["url"] != testURL {
		t.Fatalf("snippet url: %v", entry)
	}

	// The generic snippet is the full document shape, valid JSON.
	raw := []byte(GenericSnippet(testURL))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("generic snippet not valid JSON: %v\n%s", err, raw)
	}

	// Manual clients produce no snippet (there is nothing to write).
	home = t.TempDir()
	e = fakeEnv(t, home)
	if err := os.MkdirAll(filepath.Join(e.ConfigDir, "Claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range Detect(e) {
		if c.Manual() && c.Snippet(testURL) != "" {
			t.Fatalf("manual client produced a snippet: %q", c.ID)
		}
	}
}
