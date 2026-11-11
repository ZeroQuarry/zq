package mcpclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const codexFixture = `# Codex configuration — comments like this must survive.
model = "gpt-5.3"

[mcp_servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem"]

[mcp_servers.corp]
url = "https://zq.corp.example.com/mcp" # trailing comments too

# more business below
[profiles.fast]
model = "gpt-5.3-mini"
`

func mustMergeTOML(t *testing.T, path string) Result {
	t.Helper()
	res, err := mergeTOML(path, ServerName, testURL)
	if err != nil {
		t.Fatalf("mergeTOML: %v", err)
	}
	return res
}

func TestMergeTOMLFreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	res := mustMergeTOML(t, path)
	if res.Status != StatusAdded {
		t.Fatalf("status = %q, want added", res.Status)
	}
	if res.Backup != "" {
		t.Fatalf("fresh file must not create a backup, got %q", res.Backup)
	}
	got := string(readBytes(t, path))
	want := "[mcp_servers." + ServerName + "]\nurl = \"" + testURL + "\"\n"
	if got != want {
		t.Fatalf("fresh file = %q, want %q", got, want)
	}
}

func TestMergeTOMLFreshFileCreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".codex", "config.toml")
	if _, err := mergeTOML(path, ServerName, testURL); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("not created: %v", err)
	}
}

func TestMergeTOMLAppendPreservesEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, codexFixture)

	res := mustMergeTOML(t, path)
	if res.Status != StatusAdded {
		t.Fatalf("status = %q, want added", res.Status)
	}
	if res.Backup == "" {
		t.Fatal("an append must back up the original first")
	}
	got := string(readBytes(t, path))
	// Everything before the appended section is byte-identical, and the
	// fixture's comments are all still there.
	if !strings.HasPrefix(got, codexFixture) {
		t.Fatalf("original content was altered:\n%s", got)
	}
	if !strings.Contains(got, "# Codex configuration — comments like this must survive.") ||
		!strings.Contains(got, "# more business below") {
		t.Fatalf("comments lost:\n%s", got)
	}
	wantSection := "[mcp_servers." + ServerName + "]\nurl = \"" + testURL + "\"\n"
	if !strings.HasSuffix(got, wantSection) {
		t.Fatalf("section not appended cleanly:\n%s", got)
	}
}

func TestMergeTOMLIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, codexFixture)
	mustMergeTOML(t, path)
	afterFirst := string(readBytes(t, path))

	res := mustMergeTOML(t, path)
	if res.Status != StatusUnchanged {
		t.Fatalf("second run status = %q, want unchanged", res.Status)
	}
	if res.Backup != "" {
		t.Fatalf("no backup on an unchanged file, got %q", res.Backup)
	}
	if got := string(readBytes(t, path)); got != afterFirst {
		t.Fatalf("second run changed the file:\n%s", got)
	}
}

func TestMergeTOMLReplacesURLLineOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, `# my codex config
[mcp_servers.`+ServerName+`]
url = "https://old.example.com/mcp"
# a note about the server below
command = "should-not-exist"

[mcp_servers.other]
url = "https://other.example.com/mcp"
`)
	res := mustMergeTOML(t, path)
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	got := string(readBytes(t, path))
	if !strings.Contains(got, "url = \""+testURL+"\"") {
		t.Fatalf("url not updated:\n%s", got)
	}
	if strings.Contains(got, "old.example.com") {
		t.Fatalf("old url still present:\n%s", got)
	}
	// Sibling tables and comments untouched.
	if !strings.Contains(got, "url = \"https://other.example.com/mcp\"") ||
		!strings.Contains(got, "# a note about the server below") {
		t.Fatalf("collateral damage:\n%s", got)
	}
}

func TestMergeTOMLLeavesStdioEntryAlone(t *testing.T) {
	// A hand-rolled zeroquarry entry without a url key is settings this
	// package does not own: skip, change nothing.
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "[mcp_servers." + ServerName + "]\ncommand = \"zq\"\nargs = [\"mcp\"]\n"
	writeInitial(t, path, original)

	res := mustMergeTOML(t, path)
	if res.Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
	if got := string(readBytes(t, path)); got != original {
		t.Fatalf("skipped entry was modified:\n%s", got)
	}
}

func TestMergeTOMLQuotedKeyMatched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, `[mcp_servers."`+ServerName+`"]
url = "`+testURL+`"
`)
	res := mustMergeTOML(t, path)
	if res.Status != StatusUnchanged {
		t.Fatalf("status = %q, want unchanged", res.Status)
	}
}

func TestMergeTOMLInlineEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, `[mcp_servers]
filesystem = { command = "npx" }
`+ServerName+` = { url = "https://old.example.com/mcp", bearer_token_env_var = "KEEP_ME" }
`)

	res := mustMergeTOML(t, path)
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	got := string(readBytes(t, path))
	if !strings.Contains(got, `url = "`+testURL+`"`) {
		t.Fatalf("inline url not updated:\n%s", got)
	}
	if !strings.Contains(got, "KEEP_ME") {
		t.Fatalf("sibling inline keys dropped:\n%s", got)
	}

	// And idempotent.
	after := string(readBytes(t, path))
	if res := mustMergeTOML(t, path); res.Status != StatusUnchanged {
		t.Fatalf("second run status = %q", res.Status)
	}
	if got := string(readBytes(t, path)); got != after {
		t.Fatalf("second run changed the file:\n%s", got)
	}
}

func TestMergeTOMLInlineStdioSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "[mcp_servers]\n" + ServerName + " = { command = \"zq\", args = [\"mcp\"] }\n"
	writeInitial(t, path, original)
	res := mustMergeTOML(t, path)
	if res.Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
	if got := string(readBytes(t, path)); got != original {
		t.Fatalf("skipped entry was modified:\n%s", got)
	}
}

func TestMergeTOMLBackupNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, "[mcp_servers."+ServerName+"]\nurl = \"https://v1.example.com/mcp\"\n")
	first := mustMergeTOML(t, path)
	if first.Status != StatusUpdated || first.Backup == "" {
		t.Fatalf("first run: %+v", first)
	}
	v1 := string(readBytes(t, first.Backup))

	if _, err := mergeTOML(path, ServerName, testURLAlt); err != nil {
		t.Fatal(err)
	}
	if got := string(readBytes(t, first.Backup)); got != v1 {
		t.Fatalf("backup was overwritten:\n%s", got)
	}
}

// The rewritten url line keeps its trailing comment — "comments
// survive" has to hold for the line being rewritten, too.
func TestMergeTOMLKeepsTrailingCommentOnURLLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, "[mcp_servers."+ServerName+"]\n"+
		`url = "https://old.example.com/mcp"  # self-hosted endpoint`+"\n")

	res := mustMergeTOML(t, path)
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want updated", res.Status)
	}
	got := string(readBytes(t, path))
	if !strings.Contains(got, `url = "`+testURL+`"  # self-hosted endpoint`) {
		t.Fatalf("comment dropped from the rewritten line:\n%s", got)
	}
}

// A "#" inside a quoted value is part of the value, not a comment.
func TestMergeTOMLHashInsideURLIsNotAComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, "[mcp_servers."+ServerName+"]\n"+
		`url = "https://old.example.com/mcp#frag"`+"\n")

	if _, err := mergeTOML(path, ServerName, testURL); err != nil {
		t.Fatal(err)
	}
	got := string(readBytes(t, path))
	if !strings.Contains(got, `url = "`+testURL+`"`+"\n") {
		t.Fatalf("url with fragment not rewritten cleanly:\n%s", got)
	}
}

// The inline rewrite inserts the new URL literally: $ in the URL must
// not be read as a regexp replacement expansion (which would splice
// the old URL into the new one).
func TestMergeTOMLInlineURLWithDollarIsLiteral(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeInitial(t, path, "[mcp_servers]\n"+
		ServerName+` = { url = "https://old.example.com/mcp?key=$1" }`+"\n")

	newURL := "https://new.example.com/mcp?key=$TOKEN"
	if _, err := mergeTOML(path, ServerName, newURL); err != nil {
		t.Fatal(err)
	}
	got := string(readBytes(t, path))
	if !strings.Contains(got, `url = "`+newURL+`"`) {
		t.Fatalf("replacement not literal:\n%s", got)
	}
	if strings.Contains(got, "old.example.com") {
		t.Fatalf("old url spliced into the new one:\n%s", got)
	}
}
