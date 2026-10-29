// Package cookies normalizes operator-pasted cookie material into the
// canonical `k=v; k2=v2` string a scan's config carries.
//
// Every browser surface copies a different shape, and asking the
// operator to reformat by hand is the worst version of the flow:
//
//   - Chrome/Edge DevTools → Application → Cookies: select-all + copy
//     gives a TSV table (Name, Value, Domain, Path, HttpOnly, …) — the
//     one surface that includes HttpOnly session cookies.
//   - Firefox DevTools → Storage → Cookies: the same TSV idea.
//   - `copy(document.cookie)` run in a page's devtools: cookie-header
//     format, but HttpOnly cookies are invisible to it.
//   - Cookie-export extensions: JSON, usually
//     `[{"name": …, "value": …}]`, or the Netscape cookie-file format
//     (curl / "cookies.txt" exports: 7 tab-separated columns
//     `domain  flag  path  secure  expiry  name  value` — recognized
//     by its TRUE/FALSE flag column and parsed from the name/value
//     columns, not the first two).
//
// Normalize accepts all of the good shapes and returns the canonical
// string. It is idempotent over canonical input, and unrecognized text
// passes through untouched rather than being mangled: the scan's own
// Cookie handling stays the authority for whatever it holds.
package cookies

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Normalize maps whatever the operator pasted to the canonical cookie
// string. Empty/blank in → "".
func Normalize(text string) string {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return ""
	}

	var pairs [][2]string
	if raw[0] == '[' || raw[0] == '{' {
		pairs = pairsFromJSON(raw)
	}
	if len(pairs) == 0 {
		pairs = pairsFromLines(raw)
	}
	if len(pairs) == 0 {
		return raw
	}
	return joinPairs(pairs)
}

// Canonical is the strict half of Normalize: it returns the canonical
// string only when actual cookie pairs were parsed, and false when the
// input passed through unrecognized. Importers use it to fail loudly
// on junk instead of storing a garbage cookie string; the interactive
// paste path keeps Normalize's passthrough (the scan's own Cookie
// handling is the authority for what a human deliberately pasted).
func Canonical(text string) (string, bool) {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return "", false
	}
	var pairs [][2]string
	if raw[0] == '[' || raw[0] == '{' {
		pairs = pairsFromJSON(raw)
	}
	if len(pairs) == 0 {
		pairs = pairsFromLines(raw)
	}
	if len(pairs) == 0 {
		return "", false
	}
	return joinPairs(pairs), true
}

// NormalizeJSON is the JSON-only half of Normalize: it returns the
// canonical string and whether the JSON actually carried cookie pairs.
// Importers use the bool to fail loudly on parseable-but-unusable JSON
// (a typo'd export) instead of silently uploading the raw bytes as a
// cookie string.
func NormalizeJSON(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || (raw[0] != '[' && raw[0] != '{') {
		return "", false
	}
	pairs := pairsFromJSON(raw)
	if len(pairs) == 0 {
		return "", false
	}
	return joinPairs(pairs), true
}

func joinPairs(pairs [][2]string) string {
	// Later occurrences win (a re-pasted fresher value overwrites the
	// earlier one) while keeping first-seen order.
	ordered := make(map[string]string, len(pairs))
	var names []string
	for _, kv := range pairs {
		if _, seen := ordered[kv[0]]; !seen {
			names = append(names, kv[0])
		}
		ordered[kv[0]] = kv[1]
	}
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(ordered[name])
	}
	return b.String()
}

// pairsFromJSON parses cookie-exporter JSON: a list of {name, value}
// objects, or a plain {name: value} map. Anything else parses to
// nothing here and falls through to line parsing. Map entries are
// emitted in sorted key order: Go map iteration is randomized, and
// two normalizations of the same paste must produce the same string
// (an upload is content-addressable by eye in support and audits).
func pairsFromJSON(raw string) [][2]string {
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	var pairs [][2]string
	switch obj := parsed.(type) {
	case map[string]any:
		keys := make([]string, 0, len(obj))
		for key := range obj {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			switch v := obj[key].(type) {
			case string:
				pairs = append(pairs, [2]string{strings.TrimSpace(key), v})
			case float64:
				pairs = append(pairs, [2]string{strings.TrimSpace(key), trimFloat(v)})
			}
		}
	case []any:
		for _, item := range obj {
			entry, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := entry["name"].(string)
			value, _ := entry["value"].(string)
			if strings.TrimSpace(name) != "" {
				pairs = append(pairs, [2]string{strings.TrimSpace(name), value})
			}
		}
	}
	return pairs
}

// pairsFromLines parses the line-oriented shapes: DevTools TSV (first
// two columns are Name/Value; the Domain/Path/Size columns are dropped,
// and the header row is skipped), Netscape cookie-file rows (name/value
// are the LAST two of seven columns), cookie-header strings on one or
// many lines (k=v; k2=v2), and plain name=value per line. Cookie values
// may contain "=" (partition keeps the tail); tabs never appear inside
// a real cookie value, so a TSV row's second field is exactly the value.
func pairsFromLines(raw string) [][2]string {
	var pairs [][2]string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") { // Netscape files carry comments
			continue
		}
		if strings.Contains(line, "\t") {
			fields := strings.Split(line, "\t")
			for i := range fields {
				fields[i] = strings.TrimSpace(fields[i])
			}
			flag := ""
			if len(fields) > 1 {
				flag = strings.ToUpper(fields[1])
			}
			if len(fields) >= 7 && (flag == "TRUE" || flag == "FALSE") {
				// Netscape cookie-file row: domain flag path secure
				// expiry name value — the name/value are columns 5/6.
				pairs = append(pairs, [2]string{fields[5], fields[6]})
				continue
			}
			name := fields[0]
			if name == "" || strings.EqualFold(name, "name") { // the DevTools header row
				continue
			}
			value := ""
			if len(fields) > 1 {
				value = fields[1]
			}
			pairs = append(pairs, [2]string{name, value})
			continue
		}
		for _, segment := range strings.Split(line, ";") {
			segment = strings.TrimSpace(segment)
			name, value, found := strings.Cut(segment, "=")
			if !found {
				continue
			}
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			pairs = append(pairs, [2]string{name, strings.TrimSpace(value)})
		}
	}
	return pairs
}

// trimFloat renders a JSON number the way Python's str() would for the
// integral values cookie exporters actually emit (1 not 1e+00).
func trimFloat(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
