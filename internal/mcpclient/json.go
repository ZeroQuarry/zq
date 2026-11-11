package mcpclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// mergeJSON adds or updates the serverName entry inside the
// "mcpServers" object of the JSON config at path, leaving every other
// byte of meaning in the file alone.
//
// Semantics:
//   - missing file        → create it with just the mcpServers object
//   - entry absent        → added (backup of the original, if any)
//   - entry present       → url/type fields updated IN PLACE; any extra
//     fields the user put in the entry (headers, env, ...) survive.
//     Byte-identical result → unchanged, nothing written at all.
//   - "mcpServers" not an object → error, nothing written
//   - file not valid JSON → error, nothing written
func mergeJSON(path, serverName string, entry map[string]any) (Result, error) {
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		doc := map[string]any{
			"mcpServers": map[string]any{serverName: entry},
		}
		if err := writeJSONDoc(path, doc, false); err != nil {
			return Result{}, err
		}
		return Result{Status: StatusAdded, Entry: compactJSON(entry)}, nil
	case err != nil:
		return Result{}, err
	}

	// UseNumber keeps every number as its exact literal text: a
	// re-encoded document must not rewrite someone's 20-digit id as a
	// rounded float64.
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return Result{}, fmt.Errorf(
			"%s is not valid JSON (%v) — fix or remove it, then re-run", path, err)
	}
	// Exactly one JSON value per file. Trailing content is corruption,
	// and rewriting the file would silently drop it — say so instead.
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Result{}, fmt.Errorf(
			"%s has content after the JSON document — fix or remove it, then re-run", path)
	}

	var servers map[string]any
	if existing, present := doc["mcpServers"]; present && existing != nil {
		m, ok := existing.(map[string]any)
		if !ok {
			return Result{}, fmt.Errorf(
				"%s: %q is not a JSON object — refusing to edit it", path, "mcpServers")
		}
		servers = m
	} else {
		servers = map[string]any{}
		doc["mcpServers"] = servers
	}

	hadEntry := false
	merged := entry
	if existing, present := servers[serverName]; present {
		hadEntry = true
		if m, ok := existing.(map[string]any); ok {
			if _, hasURL := m["url"]; !hasURL {
				// A hand-registered entry with no url (a stdio server,
				// say) is settings this package does not own — the same
				// rule as the TOML path. Overlaying a transport onto a
				// command would leave a config that cannot work.
				return Result{Status: StatusSkipped, Entry: compactJSON(entry)}, nil
			}
			// Keep the user's own fields (headers, env, ...). The drop
			// set is derived from our entry: command/args are always
			// stale next to a url, and a transport type is stale only
			// when our entry supplies the replacement — a client whose
			// shape carries no type (Cursor) must not have the user's
			// transport hint silently deleted.
			_, typeOurs := entry["type"]
			merged = make(map[string]any, len(m)+len(entry))
			for k, v := range m {
				stale := k == "command" || k == "args" || (k == "type" && typeOurs)
				if !stale {
					merged[k] = v
				}
			}
			for k, v := range entry {
				merged[k] = v
			}
		}
		if jsonEqual(existing, merged) {
			return Result{Status: StatusUnchanged, Entry: compactJSON(merged)}, nil
		}
	}

	backup, created, err := backupOnce(path)
	if err != nil {
		return Result{}, fmt.Errorf("backing up %s: %w", path, err)
	}
	if !created {
		backup = ""
	}
	servers[serverName] = merged
	if err := writeJSONDoc(path, doc, true); err != nil {
		return Result{}, err
	}
	status := StatusUpdated
	if !hadEntry {
		status = StatusAdded
	}
	return Result{Status: status, Backup: backup, Entry: compactJSON(merged)}, nil
}

// writeJSONDoc re-encodes the whole document. JSON object key order is
// not semantic, so re-sorting keys is fine; the backup holds the
// original bytes. The file mode is preserved when the file exists.
func writeJSONDoc(path string, doc map[string]any, exists bool) error {
	out, err := encodeJSON(doc, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(out), modeFor(path, exists))
}

// jsonEqual compares decoded JSON values structurally (object key
// order is irrelevant). Marshal is the canonicalizer: map keys sort,
// and both sides have been through Unmarshal, so number shapes line
// up.
func jsonEqual(a, b any) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ab) == string(bb)
}
