// Package cli is the zq command surface:
//
//	zq login                 device-flow sign-in (browser does the auth)
//	zq logout                revoke + clear the stored token
//	zq whoami                verify credentials / CI sanity check
//	zq creds add identity    upload auth material → auth_identity_id
//	zq creds add git         upload git credential → git_credential_id
//	zq creds list            list stored references (metadata only)
//
// Output contract: `creds add` writes ONLY the reference id to stdout.
// Every prompt, progress line, and error goes to stderr. Credential
// values exist in three places and nowhere else: the hidden prompt /
// the --from-file bytes or ZQ_KEY, the process's request body on the
// wire, and the platform's encrypted store.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/ZeroQuarry/zq/internal/auth"
	"github.com/ZeroQuarry/zq/internal/config"
	"github.com/ZeroQuarry/zq/internal/platform"
	"github.com/ZeroQuarry/zq/internal/prompt"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// ExitError carries a process exit code with a message already fit to
// print.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

func failf(format string, args ...any) error {
	return &ExitError{Code: 1, Msg: fmt.Sprintf(format, args...)}
}

// errHelp signals a help request (-h/--help): exit 0, print nothing.
var errHelp = &ExitError{Code: 0}

// env resolves the deployment: --api flag > ZQ_URL > saved settings >
// the hosted default. Self-hosted deployments never need more than
// this. The result is validated so a scheme-less paste
// (`--api api.example.com`) fails with a fix-it message instead of a
// raw transport error.
func env(apiFlag string) (string, error) {
	var base string
	switch {
	case apiFlag != "":
		base = apiFlag
	case os.Getenv("ZQ_URL") != "":
		base = os.Getenv("ZQ_URL")
	default:
		settings, err := config.LoadSettings()
		if err != nil {
			return "", err
		}
		base = settings.APIBase
		if base == "" {
			return config.DefaultAPIBase, nil
		}
	}
	base = strings.TrimRight(base, "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", failf("%q is not a valid platform URL — include the scheme, e.g. https://%s", base, hostOrPlaceholder(base))
	}
	return base, nil
}

func hostOrPlaceholder(base string) string {
	return strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
}

// staticKey resolves the CI/headless credential from the environment.
// There is no --token flag: a static API key must never ride the
// command line (flags leak via shell history and process listings).
func staticKey() string {
	return os.Getenv("ZQ_KEY")
}

// resolveClient builds an authenticated platform client or returns a
// "how to sign in" error.
func resolveClient(ctx context.Context, apiBase string, stderr io.Writer) (*platform.Client, error) {
	b, err := auth.Resolve(ctx, platform.HTTP(), staticKey(), apiBase)
	if err != nil {
		if errors.Is(err, auth.ErrNotLoggedIn) {
			return nil, failf(
				"not signed in. Run `zq login`, or export ZQ_KEY=zq_... with a user API key\n(Account → API keys).")
		}
		return nil, err
	}
	if err := b.Persist(); err != nil {
		fmt.Fprintf(stderr, "warning: could not persist the refreshed token: %v\n", err)
	}
	return platform.New(apiBase, b), nil
}

// Main runs the CLI and returns the process exit code.
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "login":
		return runCommand(ctx, args[1:], stdin, stdout, stderr, cmdLogin)
	case "logout":
		return runCommand(ctx, args[1:], stdin, stdout, stderr, cmdLogout)
	case "whoami":
		return runCommand(ctx, args[1:], stdin, stdout, stderr, cmdWhoami)
	case "creds":
		return runCreds(ctx, args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "zq %s\n", Version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "zq: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

// runCommand gives the command its context and maps errors to exit
// codes. Each command owns its flag parsing: it builds a FlagSet,
// registers the shared flags, and calls c.parse(fs).
func runCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, run func(c *cmdCtx) error) int {
	c := &cmdCtx{
		ctx:     ctx,
		stdout:  stdout,
		stderr:  stderr,
		streams: prompt.New(stdin, stderr),
		args:    args,
	}
	if err := run(c); err != nil {
		if errors.Is(err, errHelp) {
			return 0
		}
		printErr(stderr, err)
		return exitCodeOf(err)
	}
	return 0
}

func exitCodeOf(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}

func printErr(stderr io.Writer, err error) {
	fmt.Fprintf(stderr, "zq: %v\n", err)
}

// cmdCtx is what every command gets: the raw args, the streams to talk
// to, and — after parse — the resolved deployment and credentials.
type cmdCtx struct {
	ctx context.Context

	stdout  io.Writer
	stderr  io.Writer
	streams *prompt.Streams
	args    []string

	apiBase   string
	apiFlag   string
}

// parse consumes the command's flags, then resolves --api/ZQ_URL and
// ZQ_KEY exactly once. -h/--help maps to exit 0.
func (c *cmdCtx) parse(fs *flag.FlagSet) error {
	fs.SetOutput(c.stderr)
	fs.StringVar(&c.apiFlag, "api", "", "Platform base URL (default: ZQ_URL, then the saved login, then "+config.DefaultAPIBase+")")
	if err := fs.Parse(c.args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelp
		}
		return &ExitError{Code: 2, Msg: "flag error"}
	}
	base, err := env(c.apiFlag)
	if err != nil {
		return err
	}
	c.apiBase = base
	return nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `zq %s — companion CLI for ZeroQuarry

Move scan credentials to the platform WITHOUT the web app and WITHOUT
the values ever entering agent context: the CLI uploads them over
HTTPS and prints only the reference id. Your agent sees the reference;
the platform attaches the values itself at scan time.

Usage:
  zq login [--api URL]                    device-flow sign-in (browser)
  zq logout                               revoke and forget the login
  zq whoami                               verify credentials
  zq creds add identity [flags]           → prints auth_identity_id
  zq creds add git [flags]                → prints git_credential_id
  zq creds list identity|git              list references (no values)

Common flags:
  --api URL     target a self-hosted deployment (env: ZQ_URL)

Credential values are only ever read from hidden prompts or
--from-file — never command-line flags (flags leak via shell history
and process listings).

Run `+"`"+`zq creds add identity -h`+"`"+` / `+"`"+`zq creds add git -h`+"`"+` for the full
flag lists.
`, Version)
}
