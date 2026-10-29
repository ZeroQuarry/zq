package prompt

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func newStreams(input string) (*Streams, *strings.Builder) {
	errBuf := &strings.Builder{}
	s := New(strings.NewReader(input), errBuf)
	return s, errBuf
}

func TestSecretFromPipe(t *testing.T) {
	s, errBuf := newStreams("hunter2\n")
	got, err := s.Secret("Password")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hunter2" {
		t.Fatalf("got %q", got)
	}
	// The prompt rendered on stderr; the value did not.
	if !strings.Contains(errBuf.String(), "Password") {
		t.Errorf("prompt missing: %q", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "hunter2") {
		t.Errorf("secret echoed to output: %q", errBuf.String())
	}
}

func TestLineReadsEchoedInput(t *testing.T) {
	s, _ := newStreams("git.corp.example.com\n")
	got, err := s.Line("Host")
	if err != nil {
		t.Fatal(err)
	}
	if got != "git.corp.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestSharedBufferAcrossPrompts(t *testing.T) {
	// Multiple prompts on one piped stdin: buffered input must survive
	// across calls (the classic per-call bufio.Reader bug).
	s, _ := newStreams("user\npass\n")
	u, err := s.Line("User")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Secret("Pass")
	if err != nil {
		t.Fatal(err)
	}
	if u != "user" || p != "pass" {
		t.Fatalf("got %q / %q", u, p)
	}
}

func TestChoose(t *testing.T) {
	s, _ := newStreams("\n") // empty line → default first option
	idx, err := s.Choose("Pick", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Fatalf("default should be 0, got %d", idx)
	}

	s, _ = newStreams("nope\n2\n") // invalid then valid
	idx, err = s.Choose("Pick", []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("got %d", idx)
	}
}

// A piped run whose stdin runs dry must FAIL, not silently pick
// option 1 — that silent default once sent a credential to whichever
// project happened to sort first.
func TestChooseEOFFailsLoudly(t *testing.T) {
	s, _ := newStreams("")
	if _, err := s.Choose("Pick", []string{"a", "b"}); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("want ErrEmptyInput, got %v", err)
	}
	// …and the error tells the user what to do instead.
	_, errBuf := newStreams("")
	_, err := newStreamsErr(errBuf).Choose("Pick", []string{"a", "b"})
	if err == nil || !strings.Contains(err.Error(), "--project") {
		t.Fatalf("error should suggest the explicit flag, got %v", err)
	}
}

func newStreamsErr(errBuf *strings.Builder) *Streams {
	return New(strings.NewReader(""), errBuf)
}

func TestSecretMultilinePEM(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----\nextra after\n"
	s, _ := newStreams(pem)
	got, err := s.SecretMultiline("Paste key")
	if err != nil {
		t.Fatal(err)
	}
	want := "-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// The shared buffer kept the remainder for later prompts.
	rest, err := s.Line("Next")
	if err != nil {
		t.Fatal(err)
	}
	if rest != "extra after" {
		t.Fatalf("lost the buffered remainder: %q", rest)
	}
}

func TestSecretMultilineEOFWithoutMarker(t *testing.T) {
	s, _ := newStreams("line1\nline2")
	got, err := s.SecretMultiline("Paste")
	if err != nil {
		t.Fatal(err)
	}
	if got != "line1\nline2" {
		t.Fatalf("got %q", got)
	}
}

func TestIsTerminalFalseForPipes(t *testing.T) {
	s, _ := newStreams("")
	if s.IsTerminal() {
		t.Error("a strings.Reader is not a terminal")
	}
	s2, _ := newStreams("")
	s2.Stdin = os.Stdin
	_ = s2 // (os.Stdin in `go test` is not a TTY either; no assert)
}
