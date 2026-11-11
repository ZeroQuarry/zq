package mcpclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testURL = "https://mcp.zeroquarry.com/"
const testURLAlt = "https://zq.corp.example.com/mcp"

func writeInitial(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMergeJSON(t *testing.T, path string) Result {
	t.Helper()
	res, err := mergeJSON(path, ServerName, map[string]any{"url": testURL})
	if err != nil {
		t.Fatalf("mergeJSON: %v", err)
	}
	return res
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeDoc(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	// Same decoding rules as production (UseNumber) so comparisons see
	// the exact number literals that will be re-encoded.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("resulting file is not valid JSON: %v\n%s", err, raw)
	}
	return doc
}

func TestMergeJSONFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	res := mustMergeJSON(t, path)
	if res.Status != StatusAdded {
		t.Fatalf("status = %q, want added", res.Status)
	}
	if res.Backup != "" {
		t.Fatalf("fresh file must not create a backup, got %q", res.Backup)
	}
	doc := decodeDoc(t, readBytes(t, path))
	entry := doc["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if entry["url"] != testURL {
		t.Fatalf("url: %v", entry["url"])
	}
}

func TestMergeJSONFreshFileCreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cursor", "mcp.json")
	if _, err := mergeJSON(path, ServerName, map[string]any{"url": testURL}); err != nil {
		t.Fatalf("mergeJSON: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestMergeJSONUnchangedLeavesFileByteIdentical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	// Whitespace and key order differ from anything this package would
	// write — an unchanged verdict must not rewrite them.
	original := "{\n  \"mcpServers\": { \"" + ServerName + "\": { \"url\": \"" + testURL + "\" } }\n}\n"
	writeInitial(t, path, original)

	res := mustMergeJSON(t, path)
	if res.Status != StatusUnchanged {
		t.Fatalf("status = %q, want unchanged", res.Status)
	}
	if res.Backup != "" {
		t.Fatalf("no backup on an unchanged file, got %q", res.Backup)
	}
	if got := string(readBytes(t, path)); got != original {
		t.Fatalf("file changed:\n%s", got)
	}
}

func TestMergeJSONUpdatesEntryInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": {"`+ServerName+`": {"url": "https://old.example.com/mcp", "headers": {"X-Keep": "me"}}}}`)

	res := mustMergeJSON(t, path)
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	if res.Backup == "" {
		t.Fatal("an update must back up the original first")
	}
	// The backup holds the pre-zq bytes.
	backup := string(readBytes(t, res.Backup))
	if !strings.Contains(backup, "https://old.example.com/mcp") {
		t.Fatalf("backup lost the original: %s", backup)
	}
	// The update rewrites the url but keeps the user's own fields.
	entry := decodeDoc(t, readBytes(t, path))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if entry["url"] != testURL {
		t.Fatalf("url: %v", entry["url"])
	}
	if !reflect.DeepEqual(entry["headers"], map[string]any{"X-Keep": "me"}) {
		t.Fatalf("user fields dropped: %v", entry)
	}
}

func TestMergeJSONPreservesUnrelatedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	original := `{
  "projectHistory": {"lastOpened": "2026-11-01", "counts": [1, 2, 3600]},
  "unicode": "héllo <tag> & ampersand — kept verbatim",
  "mcpServers": {
    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]},
    "other": {"url": "https://other.example.com/mcp"}
  }
}`
	writeInitial(t, path, original)

	mustMergeJSON(t, path)
	got := decodeDoc(t, readBytes(t, path))

	want := decodeDoc(t, []byte(original))
	delete(want["mcpServers"].(map[string]any), ServerName)
	// Everything except our own entry must round-trip: unrelated top
	// level keys, unrelated servers, numbers, unicode, HTML-significant
	// characters (which must NOT be \u003c-escaped back into the file).
	delete(got["mcpServers"].(map[string]any), ServerName)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unrelated content changed:\n got %#v\nwant %#v", got, want)
	}
	if strings.Contains(string(readBytes(t, path)), `\u003c`) {
		t.Fatal("HTML escaping crept into the rewritten file")
	}
}

func TestMergeJSONCorruptFileFailsWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	broken := `{"mcpServers": {`
	writeInitial(t, path, broken)

	_, err := mergeJSON(path, ServerName, map[string]any{"url": testURL})
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("want a fix-it error, got %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error must name the file: %v", err)
	}
	if got := string(readBytes(t, path)); got != broken {
		t.Fatalf("corrupt file was modified: %s", got)
	}
	if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
		t.Fatal("no backup should exist for a refused write")
	}
}

func TestMergeJSONMCPServersNotAnObject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": ["nope"]}`)
	_, err := mergeJSON(path, ServerName, map[string]any{"url": testURL})
	if err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestMergeJSONNullMCPServersTreatedAsAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": null}`)
	res := mustMergeJSON(t, path)
	if res.Status != StatusAdded {
		t.Fatalf("status = %q, want added", res.Status)
	}
	decodeDoc(t, readBytes(t, path)) // must be valid JSON with our entry
}

func TestMergeJSONBackupNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": {"`+ServerName+`": {"url": "https://v1.example.com/mcp"}}}`)

	first := mustMergeJSON(t, path) // v1 → hosted
	if first.Status != StatusUpdated || first.Backup == "" {
		t.Fatalf("first run: %+v", first)
	}
	v1Backup := string(readBytes(t, first.Backup))

	// A later run against yet another URL updates again — the backup
	// from the first run must still hold the true original.
	if _, err := mergeJSON(path, ServerName, map[string]any{"url": testURLAlt}); err != nil {
		t.Fatal(err)
	}
	if got := string(readBytes(t, first.Backup)); got != v1Backup {
		t.Fatalf("backup was overwritten:\n%s", got)
	}
	if !strings.Contains(v1Backup, "https://v1.example.com/mcp") {
		t.Fatalf("backup content: %s", v1Backup)
	}
}

func TestMergeJSONPreservesFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": {}}`)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	mustMergeJSON(t, path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode changed to %v", info.Mode().Perm())
	}
}

func TestMergeJSONGarbageEntryReplaced(t *testing.T) {
	// A zeroquarry entry that is not an object is junk; replacing it is
	// the fix, not preserving it.
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": {"`+ServerName+`": "https://old.example.com/mcp"}}`)
	res := mustMergeJSON(t, path)
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	entry := decodeDoc(t, readBytes(t, path))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if entry["url"] != testURL {
		t.Fatalf("url: %v", entry["url"])
	}
}

// A hand-registered entry without a url (a stdio server) is settings
// this package does not own: skip it — overlaying a transport onto a
// command would leave a config that cannot work. Same rule as TOML.
func TestMergeJSONLeavesStdioEntryAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	original := `{"mcpServers": {"` + ServerName + `": {"command": "zq", "args": ["mcp"]}}}`
	writeInitial(t, path, original)

	res := mustMergeJSON(t, path)
	if res.Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
	if got := string(readBytes(t, path)); got != original {
		t.Fatalf("skipped entry was modified:\n%s", got)
	}
	if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
		t.Fatal("no backup should exist for a skipped entry")
	}
}

// A URL-shaped entry that carries leftovers of the other transport
// (e.g. from an older mixed write) is cleaned up when the url is
// rewritten: no stdio command survives next to the http entry.
func TestMergeJSONDropsStaleTransportKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": {"`+ServerName+`": {
		"command": "zq", "args": ["mcp"], "type": "sse",
		"url": "https://old.example.com/mcp", "headers": {"X-Keep": "me"}
	}}}`)

	entry := map[string]any{"type": "http", "url": testURL}
	res, err := mergeJSON(path, ServerName, entry)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	got := decodeDoc(t, readBytes(t, path))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if got["url"] != testURL || got["type"] != "http" {
		t.Fatalf("entry: %v", got)
	}
	for _, stale := range []string{"command", "args"} {
		if _, ok := got[stale]; ok {
			t.Fatalf("stale key %q survived: %v", stale, got)
		}
	}
	if !reflect.DeepEqual(got["headers"], map[string]any{"X-Keep": "me"}) {
		t.Fatalf("user fields dropped: %v", got)
	}
}

// The type key is the user's unless our entry supplies the
// replacement: clients whose shape carries no type (Cursor) must not
// have an existing transport hint silently deleted — if someone points
// --mcp-url at an SSE endpoint, the entry must still say SSE.
func TestMergeJSONKeepsTypeWhenEntryHasNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"mcpServers": {"`+ServerName+`": {"type": "sse", "url": "https://old.example.com/mcp"}}}`)

	res, err := mergeJSON(path, ServerName, map[string]any{"url": testURL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	got := decodeDoc(t, readBytes(t, path))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if got["url"] != testURL {
		t.Fatalf("url: %v", got["url"])
	}
	if got["type"] != "sse" {
		t.Fatalf("transport hint was deleted: %v", got)
	}

	// And the same shape is idempotent: an unchanged verdict, no write.
	res, err = mergeJSON(path, ServerName, map[string]any{"url": testURL})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUnchanged {
		t.Fatalf("second run status = %q, want unchanged", res.Status)
	}
}

// The re-encoded document must not round-trip numbers through float64:
// a big id keeps its exact digits.
func TestMergeJSONKeepsNumberPrecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeInitial(t, path, `{"big": 12345678901234567890, "mcpServers": {}}`)

	mustMergeJSON(t, path)
	got := string(readBytes(t, path))
	if !strings.Contains(got, "12345678901234567890") {
		t.Fatalf("big integer was rewritten: %s", got)
	}
}
