package cookies

import (
	"strings"
	"testing"
)

// The conformance suite: every browser/export shape the normalizer
// promises to handle, with the canonical output each must produce. A
// paste accepted here must behave identically no matter which surface
// it was copied from.
func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"blank", "   \n\t", ""},
		{
			"document.cookie string",
			"session=abc123; theme=dark; tz=UTC",
			"session=abc123; theme=dark; tz=UTC",
		},
		{"idempotent over canonical", "a=1; b=2", "a=1; b=2"},
		{
			"multi-line k=v",
			"a=1\nb=2",
			"a=1; b=2",
		},
		{
			"value containing =",
			"token=abc=def=ghi",
			"token=abc=def=ghi",
		},
		{
			"devtools TSV with header row",
			"Name\tValue\tDomain\tPath\tExpires\tSize\tHttpOnly\tSecure\tSameSite\nsession\tabc123\thost\t/\t\t16\t✓\t✓\tLax",
			"session=abc123",
		},
		{
			"devtools TSV two rows",
			"Name\tValue\na\t1\nb\t2",
			"a=1; b=2",
		},
		{
			"netscape cookie file",
			"# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tTRUE\t1893456000\tsession\tabc123\n.example.com\tTRUE\t/\tFALSE\t0\tother\tx=y",
			"session=abc123; other=x=y",
		},
		{
			"json export list",
			`[{"name": "session", "value": "abc123"}, {"name": "tz", "value": "UTC"}]`,
			"session=abc123; tz=UTC",
		},
		{
			"json export map (sorted key order)",
			`{"session": "abc123", "count": 3}`,
			"count=3; session=abc123",
		},
		{
			"later occurrence wins, first order kept",
			"a=1\nb=2\na=9",
			"a=9; b=2",
		},
		{
			"unrecognized passes through",
			"this is not cookies at all",
			"this is not cookies at all",
		},
		{
			"comments and blanks skipped",
			"# a comment\n\na=1",
			"a=1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Normalize(tc.in); got != tc.want {
				t.Errorf("Normalize(%q) =\n  %q\nwant:\n  %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeJSON(t *testing.T) {
	// Map exports come out in sorted key order: two normalizations of
	// the same paste must produce the same string (Go map iteration is
	// randomized, and a nondeterministic credential string is a
	// support and audit headache).
	if got, ok := NormalizeJSON(`{"session": "abc", "n": 2}`); !ok || got != "n=2; session=abc" {
		t.Errorf("map export: got %q ok=%v", got, ok)
	}
	if got, ok := NormalizeJSON(`{"z": "1", "a": "2", "m": "3"}`); !ok || got != "a=2; m=3; z=1" {
		t.Errorf("sorted order: got %q ok=%v", got, ok)
	}
	if got, ok := NormalizeJSON(`[{"name": "s", "value": "1"}]`); !ok || got != "s=1" {
		t.Errorf("list export: got %q ok=%v", got, ok)
	}
	// Parseable but unusable JSON says so (callers fail loudly).
	if _, ok := NormalizeJSON(`{"nonsense": true}`); ok {
		t.Error("bool-valued object should not count as cookies")
	}
	if _, ok := NormalizeJSON(`[{"nope": 1}]`); ok {
		t.Error("nameless list entries should not count as cookies")
	}
	// Non-JSON never counts.
	if _, ok := NormalizeJSON("a=1"); ok {
		t.Error("plain text is not JSON cookies")
	}
}

func TestNormalizeIdempotent(t *testing.T) {
	shapes := []string{
		"session=abc; theme=dark",
		"Name\tValue\nsession\tabc",
		`[{"name":"session","value":"abc"}]`,
		".e\tTRUE\t/\tTRUE\t0\tsession\tabc",
	}
	for _, s := range shapes {
		once := Normalize(s)
		twice := Normalize(once)
		if once != twice {
			t.Errorf("not idempotent for %q: %q -> %q", s, once, twice)
		}
		if strings.Contains(once, "\t") {
			t.Errorf("tabs survived normalization: %q", once)
		}
	}
}
