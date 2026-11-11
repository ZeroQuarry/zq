package mcpclient

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// mergeTOML adds or updates the [mcp_servers.<serverName>] table in
// the Codex config at path. Codex config files are hand-edited and
// full of comments, so instead of parse→re-encode (which would strip
// them, and would need a TOML dependency) this does line-level
// surgery on the narrow shape MCP server tables take:
//
//   - missing file                          → create it with the table
//   - no such table                         → append it (everything
//     before it stays byte-identical)
//   - table exists, url matches             → unchanged, nothing written
//   - table exists, url differs             → that one url line changes
//   - table exists, no url key (a stdio     → skipped: settings this
//     server, say)                            package doesn't recognize
//     are never overridden
//   - name declared inline under the        → same compare/replace,
//     [mcp_servers] table                     preserving the other keys
//
// Quoted-key variants ([mcp_servers."name"]) are matched too.
func mergeTOML(path, serverName, serverURL string) (Result, error) {
	section := fmt.Sprintf("[mcp_servers.%s]\nurl = %q\n", serverName, serverURL)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return Result{}, err
		}
		if err := writeFileAtomic(path, []byte(section), 0o644); err != nil {
			return Result{}, err
		}
		return Result{Status: StatusAdded, Entry: section}, nil
	}
	if err != nil {
		return Result{}, err
	}
	lines := strings.Split(string(raw), "\n")

	// Dedicated table: [mcp_servers.<name>]
	if i := findTOMLTable(lines, serverName); i >= 0 {
		j, url, ok := findTableKey(lines, i, "url")
		if !ok {
			return Result{Status: StatusSkipped, Entry: section}, nil
		}
		if url == serverURL {
			return Result{Status: StatusUnchanged, Entry: section}, nil
		}
		backup, created, err := backupOnce(path)
		if err != nil {
			return Result{}, fmt.Errorf("backing up %s: %w", path, err)
		}
		if !created {
			backup = ""
		}
		lines[j] = indentOf(lines[j]) + fmt.Sprintf("url = %q", serverURL) + trailingComment(lines[j])
		if err := writeFileAtomic(path, []byte(strings.Join(lines, "\n")), modeFor(path, true)); err != nil {
			return Result{}, err
		}
		return Result{Status: StatusUpdated, Backup: backup, Entry: section}, nil
	}

	// Inline form under [mcp_servers]: name = { url = "...", ... }
	j, url, ferr := findInlineEntry(lines, serverName)
	switch {
	case errors.Is(ferr, errTOMLNoURL):
		return Result{Status: StatusSkipped, Entry: section}, nil
	case ferr == nil: // found with a url
		if url == serverURL {
			return Result{Status: StatusUnchanged, Entry: section}, nil
		}
		backup, created, err := backupOnce(path)
		if err != nil {
			return Result{}, fmt.Errorf("backing up %s: %w", path, err)
		}
		if !created {
			backup = ""
		}
		lines[j] = indentOf(lines[j]) + replaceInlineURL(strings.TrimSpace(lines[j]), serverURL)
		if err := writeFileAtomic(path, []byte(strings.Join(lines, "\n")), modeFor(path, true)); err != nil {
			return Result{}, err
		}
		return Result{Status: StatusUpdated, Backup: backup, Entry: section}, nil
	}
	// ferr: no inline entry — fall through to append.

	// Not present: append the table. The original bytes are preserved
	// verbatim up to the separator.
	backup, created, err := backupOnce(path)
	if err != nil {
		return Result{}, fmt.Errorf("backing up %s: %w", path, err)
	}
	if !created {
		backup = ""
	}
	content := string(raw)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if strings.TrimSpace(content) != "" {
		content += "\n"
	}
	content += section
	if err := writeFileAtomic(path, []byte(content), modeFor(path, true)); err != nil {
		return Result{}, err
	}
	return Result{Status: StatusAdded, Backup: backup, Entry: section}, nil
}

// isTOMLHeader reports whether a trimmed line opens a new table
// ([[array-of-tables]] counts too — anything bracketed ends the
// current table's keys).
func isTOMLHeader(trimmed string) bool {
	return strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")
}

// splitTOMLComment splits a line into its code part and its trailing
// "# ..." comment ("" when there is none). A "#" inside a quoted value
// is part of the value — a url may carry a fragment — so quotes, and
// backslash escapes inside basic strings, are honored. Only lines being
// *identified* pass through here, never values being rewritten.
func splitTOMLComment(line string) (code, comment string) {
	inDouble, inSingle := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			if inDouble {
				i++ // an escaped character never opens or closes a string
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '#':
			if !inDouble && !inSingle {
				return line[:i], line[i:]
			}
		}
	}
	return line, ""
}

// stripTOMLComment returns a line without its trailing comment,
// trimmed of surrounding space.
func stripTOMLComment(line string) string {
	code, _ := splitTOMLComment(line)
	return strings.TrimSpace(code)
}

// trailingComment returns a line's trailing "# ..." comment — with the
// whitespace that separates it from the code — so a rewritten line can
// carry its comment across. "" when there is no comment.
func trailingComment(line string) string {
	code, comment := splitTOMLComment(line)
	if comment == "" {
		return ""
	}
	trimmed := strings.TrimRight(code, " \t")
	return code[len(trimmed):] + comment
}

// findTOMLTable returns the index of the [mcp_servers.<name>] header
// line, or -1.
func findTOMLTable(lines []string, serverName string) int {
	want := "[mcp_servers." + serverName + "]"
	wantQuoted := `[mcp_servers."` + serverName + `"]`
	for i, line := range lines {
		t := stripTOMLComment(line)
		if t == want || t == wantQuoted {
			return i
		}
	}
	return -1
}

// findTableKey scans a table's own keys (stopping at the next header)
// for `key = "value"`, returning the line index and the unquoted value.
func findTableKey(lines []string, tableIdx int, key string) (lineIdx int, value string, ok bool) {
	for j := tableIdx + 1; j < len(lines); j++ {
		t := stripTOMLComment(lines[j])
		if t == "" {
			continue
		}
		if isTOMLHeader(t) {
			return 0, "", false
		}
		k, v, isKV := splitTOMLKeyValue(t)
		if isKV && k == key {
			if val, err := unquoteTOML(v); err == nil {
				return j, val, true
			}
			return 0, "", false
		}
	}
	return 0, "", false
}

// Sentinel errors from findInlineEntry: the entry was found but has no
// url key (settings this package must not override), or there is no
// inline entry at all.
var (
	errTOMLNoURL    = errors.New("no url key in the entry")
	errTOMLNotFound = errors.New("entry not found")
)

// findInlineEntry finds `name = { ... }` declared under a bare
// [mcp_servers] table. It returns the entry's line index and, when
// found, its url value — or errTOMLNoURL (entry exists, no url) or
// errTOMLNotFound (no entry).
func findInlineEntry(lines []string, serverName string) (lineIdx int, url string, err error) {
	inServers := false
	for i, line := range lines {
		t := stripTOMLComment(line)
		switch {
		case t == "":
			continue
		case isTOMLHeader(t):
			inServers = t == "[mcp_servers]"
		case inServers:
			k, v, isKV := splitTOMLKeyValue(t)
			if !isKV || k != serverName || !strings.HasPrefix(v, "{") {
				continue
			}
			url, uerr := inlineURLValue(v)
			if uerr != nil {
				return i, "", errTOMLNoURL
			}
			return i, url, nil
		}
	}
	return 0, "", errTOMLNotFound
}

var (
	inlineURLDouble = regexp.MustCompile(`url\s*=\s*"([^"]*)"`)
	inlineURLSingle = regexp.MustCompile(`url\s*=\s*'([^']*)'`)
)

// inlineURLValue extracts the url = "..." (or '...') value from an
// inline table body.
func inlineURLValue(body string) (string, error) {
	if m := inlineURLDouble.FindStringSubmatch(body); m != nil {
		return m[1], nil
	}
	if m := inlineURLSingle.FindStringSubmatch(body); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("no url key in %q", body)
}

// replaceInlineURL rewrites just the url key inside an inline table,
// keeping every other key on the line. The replacement is inserted
// literally: URLs may contain $ (template vars in query strings), and
// a regexp replacement would otherwise expand them.
func replaceInlineURL(line, serverURL string) string {
	replacement := fmt.Sprintf("url = %q", serverURL)
	if inlineURLDouble.MatchString(line) {
		return inlineURLDouble.ReplaceAllLiteralString(line, replacement)
	}
	return inlineURLSingle.ReplaceAllLiteralString(line, replacement)
}

// splitTOMLKeyValue parses "key = value" (used on lines already
// stripped of comments). Keys with dots are fine; anything without an
// "=" is not a key-value line.
func splitTOMLKeyValue(line string) (key, value string, ok bool) {
	i := strings.Index(line, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	if key == "" || strings.ContainsAny(key, " \t\"'") {
		return "", "", false
	}
	return key, strings.TrimSpace(line[i+1:]), true
}

// unquoteTOML strips the quotes from a basic ("...") or literal
// ('...') string value.
func unquoteTOML(v string) (string, error) {
	for _, q := range []byte{'"', '\''} {
		if len(v) >= 2 && v[0] == q && v[len(v)-1] == q {
			return v[1 : len(v)-1], nil
		}
	}
	return "", fmt.Errorf("not a quoted TOML string: %q", v)
}

func indentOf(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	return line[:len(line)-len(trimmed)]
}
