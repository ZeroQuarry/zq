// Package prompt reads the user's input. Every prompt renders on
// STDERR: stdout belongs to the reference id (the output contract is
// "the reference id and nothing else" — agents consume stdout while
// humans watch stderr).
//
// Secret reads use golang.org/x/term's ReadPassword when stdin is a
// terminal (no echo, no terminal history) — one line at a time, so
// even a pasted multi-line PEM key never appears on screen. When
// stdin is piped — `print $session | zq creds add identity` — there
// is no echo to disable; the pipe is the hidden channel.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// ErrEmptyInput marks "stdin ran dry before the user answered": the
// command should tell the operator to pass the value explicitly
// (non-interactive runs — the agent-facing path — must never guess).
var ErrEmptyInput = errors.New("no input")

// Streams bundles the CLI's I/O (tests swap these).
type Streams struct {
	Stdin  io.Reader
	Stderr io.Writer

	reader *bufio.Reader // shared: buffered input survives across prompts
}

// New builds streams from explicit readers/writers (tests).
func New(stdin io.Reader, stderr io.Writer) *Streams {
	return &Streams{Stdin: stdin, Stderr: stderr}
}

func (s *Streams) lines() *bufio.Reader {
	if s.reader == nil {
		s.reader = bufio.NewReader(s.Stdin)
	}
	return s.reader
}

// IsTerminal reports whether stdin is an interactive terminal.
func (s *Streams) IsTerminal() bool {
	f, ok := s.Stdin.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Secret reads one line of secret material, disabling echo on a TTY.
// The prompt (and a trailing note that input is hidden) renders on
// stderr only.
func (s *Streams) Secret(prompt string) (string, error) {
	if f, ok := s.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(s.Stderr, "%s (input hidden): ", prompt)
		raw, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(s.Stderr)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	fmt.Fprintf(s.Stderr, "%s (reading stdin): ", prompt)
	line, err := s.readLine()
	if err != nil {
		return "", err
	}
	return line, nil
}

// SecretMultiline reads secret material that spans lines (a pasted
// PEM key). On a terminal every line is read with echo disabled, so
// nothing lands in scrollback; on a pipe the buffered lines are read
// as-is. Reading stops at the -----END ...----- marker or EOF. The
// value is never stored locally — it goes straight into the upload.
func (s *Streams) SecretMultiline(promptText string) (string, error) {
	fmt.Fprintf(s.Stderr, "%s\n(reading until the -----END ...----- line; input hidden)\n", promptText)
	var lines []string
	for {
		var (
			line string
			err  error
		)
		if f, ok := s.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			raw, pwErr := term.ReadPassword(int(f.Fd()))
			err, line = pwErr, string(raw)
			fmt.Fprintln(s.Stderr)
		} else {
			line, err = s.lines().ReadString('\n')
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed != "" || err == nil {
			lines = append(lines, trimmed)
		}
		if strings.HasPrefix(strings.TrimSpace(trimmed), "-----END") {
			break
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no input")
	}
	return strings.Join(lines, "\n"), nil
}

// Line reads one echoed line of NON-secret input (labels, usernames,
// hosts). Anything secret must go through Secret.
func (s *Streams) Line(promptText string) (string, error) {
	fmt.Fprintf(s.Stderr, "%s: ", promptText)
	return s.readLine()
}

// Choose renders a numbered menu on stderr and returns the chosen
// option (0-based). An empty line accepts the default (0); stdin
// running dry is an ERROR, not a default — a piped, agent-driven run
// must not silently pick the first project. Scripts pass explicit
// flags instead.
func (s *Streams) Choose(promptText string, options []string) (int, error) {
	fmt.Fprintf(s.Stderr, "%s\n", promptText)
	for i, opt := range options {
		fmt.Fprintf(s.Stderr, "  %d) %s\n", i+1, opt)
	}
	for {
		fmt.Fprintf(s.Stderr, "Choose [1-%d, enter=1]: ", len(options))
		// Read the raw reader: EOF must be distinguishable from an
		// explicit empty line (readLine collapses the former into the
		// latter, and EOF here means "no answer", which is an error).
		raw, err := s.lines().ReadString('\n')
		if err != nil && raw == "" {
			if errors.Is(err, io.EOF) {
				return 0, fmt.Errorf("%w — answer interactively, or pass the choice explicitly "+
					"with the relevant flag (--project, --kind, or --type) for non-interactive runs", ErrEmptyInput)
			}
			return 0, err
		}
		line := strings.TrimRight(raw, "\r\n")
		if line == "" {
			return 0, nil
		}
		n, parseErr := strconv.Atoi(line)
		if parseErr == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		fmt.Fprintf(s.Stderr, "Not one of 1-%d — try again.\n", len(options))
	}
}

func (s *Streams) readLine() (string, error) {
	line, err := s.lines().ReadString('\n')
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
