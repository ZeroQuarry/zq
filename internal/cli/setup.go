package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/ZeroQuarry/zq/internal/config"
	"github.com/ZeroQuarry/zq/internal/mcpclient"
)

// cmdSetup registers the ZeroQuarry MCP server with the MCP clients
// installed on this machine. It is purely local: no login, no network,
// no secrets — which is the point, since it is the step a fresh
// install runs before any account exists.
//
// Per client it merges the "zeroquarry" entry into the client's own
// config (backup before first write, idempotent, unrelated entries
// untouched — see internal/mcpclient). Claude Desktop cannot take a
// remote server from its config file, so it gets printed guidance
// instead of a write. Clients the CLI doesn't know by name fall
// through to a generic JSON snippet.
func cmdSetup(c *cmdCtx) error {
	// This command owns its parsing: it never talks to the platform API,
	// but --api still matters — it names the deployment whose MCP
	// endpoint is being registered.
	fs := flag.NewFlagSet("zq setup", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	printOnly := fs.Bool("print-only", false, "show what would be written, change nothing")
	mcpURLFlag := fs.String("mcp-url", "", "MCP server URL to register (default: the hosted endpoint)")
	apiFlag := fs.String("api", "", "Platform base URL — when it is not the hosted default, --mcp-url names its MCP endpoint")
	if err := fs.Parse(c.args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelp
		}
		return &ExitError{Code: 2, Msg: "flag error"}
	}
	if fs.NArg() > 0 {
		return &ExitError{Code: 2, Msg: fmt.Sprintf(
			"unexpected argument %q — zq setup takes flags only", fs.Arg(0))}
	}
	serverURL, err := resolveServerURL(*mcpURLFlag, *apiFlag)
	if err != nil {
		return err
	}

	env, err := mcpclient.SystemEnv()
	if err != nil {
		return err
	}
	clients := mcpclient.Detect(env)

	if *printOnly {
		for _, cl := range clients {
			if cl.Manual() {
				fmt.Fprintf(c.stdout, "%s → no config write; %s:\n  %s\n",
					cl.DisplayName, cl.ManualHint, serverURL)
				continue
			}
			// A JSON client's file is written as one document, so the
			// preview shows the entry to merge under "mcpServers"; a
			// TOML client's snippet is the complete table.
			note := ""
			if cl.Kind == mcpclient.KindJSON {
				note = " — merge this entry under the client's \"mcpServers\" object"
			}
			fmt.Fprintf(c.stdout, "%s → %s (would add \"%s\")%s\n%s\n",
				cl.DisplayName, cl.ConfigPath, mcpclient.ServerName, note, cl.Snippet(serverURL))
		}
		fmt.Fprintf(c.stdout, "Any other MCP client → merge into its config's \"mcpServers\" object:\n%s\n",
			mcpclient.GenericSnippet(serverURL))
		fmt.Fprintln(c.stderr, "Nothing was written (--print-only).")
		printHandoff(c.stderr)
		return nil
	}

	if len(clients) == 0 {
		fmt.Fprintf(c.stdout, "No MCP clients detected. Merge this into your client's \"mcpServers\" config:\n%s\n",
			mcpclient.GenericSnippet(serverURL))
		fmt.Fprintf(c.stderr, "Known clients live in ~/.claude.json (Claude Code), ~/.cursor (Cursor), ~/.codex (Codex).\n")
		printHandoff(c.stderr)
		return nil
	}

	fmt.Fprintf(c.stderr, "Detected MCP client%s: %s\n", plural(len(clients), "", "s"), displayNames(clients))
	failures := 0
	for _, cl := range clients {
		if cl.Manual() {
			fmt.Fprintf(c.stdout, "%s: manual step (custom connectors — details on stderr)\n", cl.ID)
			fmt.Fprintf(c.stderr, "%s: %s:\n  %s\n", cl.DisplayName, cl.ManualHint, serverURL)
			continue
		}
		res, err := cl.Merge(serverURL)
		if err != nil {
			failures++
			fmt.Fprintf(c.stdout, "%s: failed\n", cl.ID)
			fmt.Fprintf(c.stderr, "%s: %v\n", cl.DisplayName, err)
			continue
		}
		if res.Backup != "" {
			fmt.Fprintf(c.stderr, "%s: backed up the original to %s\n", cl.DisplayName, res.Backup)
		}
		switch res.Status {
		case mcpclient.StatusAdded, mcpclient.StatusUpdated:
			fmt.Fprintf(c.stderr, "%s: %s \"%s\" in %s\n  %s\n",
				cl.DisplayName, res.Status, mcpclient.ServerName, cl.ConfigPath, res.Entry)
		case mcpclient.StatusSkipped:
			// Say why: the entry is not ours, and "skipped" on its own
			// leaves the user unable to tell whether the server got
			// registered at all.
			fmt.Fprintf(c.stderr, "%s: skipped — the existing %q entry has no url "+
				"(a stdio server), so it was left untouched (%s)\n",
				cl.DisplayName, mcpclient.ServerName, cl.ConfigPath)
		default:
			fmt.Fprintf(c.stderr, "%s: %s (%s)\n", cl.DisplayName, res.Status, cl.ConfigPath)
		}
		fmt.Fprintf(c.stdout, "%s: %s (%s)\n", cl.ID, res.Status, cl.ConfigPath)
	}
	printHandoff(c.stderr)
	if failures > 0 {
		return failf("%d client%s could not be configured", failures, plural(failures, "", "s"))
	}
	return nil
}

// resolveServerURL decides which MCP endpoint to register: --mcp-url
// when given (validated), else the hosted default — unless the
// deployment in play (--api > ZQ_URL > the saved login) is a
// self-hosted one. Guessing an endpoint for the wrong platform would
// misconfigure every client, so a self-hosted deployment must be told
// its MCP URL explicitly.
func resolveServerURL(mcpFlag, apiFlag string) (string, error) {
	if mcpFlag != "" {
		parsed, err := url.Parse(mcpFlag)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			return "", failf("%q is not a valid MCP server URL — include the scheme, e.g. %s",
				mcpFlag, mcpclient.DefaultServerURL)
		}
		return mcpFlag, nil
	}
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
	}
	base = strings.TrimRight(base, "/")
	if base != "" && base != config.DefaultAPIBase {
		return "", failf("%s has its own MCP endpoint — pass --mcp-url with it, "+
			"or drop --api/ZQ_URL to configure for the hosted service", base)
	}
	return mcpclient.DefaultServerURL, nil
}

func displayNames(clients []mcpclient.Client) string {
	names := make([]string, len(clients))
	for i, cl := range clients {
		names[i] = cl.DisplayName
	}
	return strings.Join(names, ", ")
}

// printHandoff is the closing line of every setup variant: from here
// the agent takes over (the platform's onboarding flow handles the
// rest).
func printHandoff(stderr io.Writer) {
	fmt.Fprintln(stderr, "\nNow tell your agent: connect to ZeroQuarry and get me started.")
	fmt.Fprintln(stderr, "Optional next step: `zq login` — or just let your agent connect.")
}
