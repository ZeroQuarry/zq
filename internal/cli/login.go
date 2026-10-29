package cli

import (
	"flag"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/ZeroQuarry/zq/internal/auth"
	"github.com/ZeroQuarry/zq/internal/config"
	"github.com/ZeroQuarry/zq/internal/platform"
)

// cmdLogin runs the device flow: discovery → authorization request →
// the user's browser does the rest → poll → store → verify.
func cmdLogin(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq login", flag.ContinueOnError)
	if err := c.parse(fs); err != nil {
		return err
	}
	ctx := c.ctx
	client := platform.HTTP()

	fmt.Fprintf(c.stderr, "Signing in to %s\n", c.apiBase)
	d, err := auth.Discover(ctx, client, c.apiBase)
	if err != nil {
		return err
	}

	dc, err := auth.StartDeviceFlow(ctx, client, d)
	if err != nil {
		return err
	}

	// The user_code and verification URI are DESIGNED to be displayed
	// (RFC 8628 §3.2) — the only thing this command ever shows.
	fmt.Fprintf(c.stderr, "\nOpen this URL to sign in:\n\n  %s\n\n", dc.VerificationURI)
	fmt.Fprintf(c.stderr, "Enter code: %s\n", dc.UserCode)
	if dc.VerificationURIComplete != "" {
		// One-click: the code is pre-filled. Still shown plainly above
		// for terminals where clicking isn't possible.
		if openBrowserFn(dc.VerificationURIComplete) {
			fmt.Fprintln(c.stderr, "(opened your browser — sign in with the account you use for ZeroQuarry)")
		}
	} else if openBrowserFn(dc.VerificationURI) {
		fmt.Fprintln(c.stderr, "(opened your browser — enter the code above)")
	}
	fmt.Fprint(c.stderr, "\nWaiting for sign-in to complete")

	tokens, err := auth.PollForToken(ctx, client, d, dc, func(wait time.Duration) {
		fmt.Fprint(c.stderr, ".")
	})
	if err != nil {
		fmt.Fprintln(c.stderr)
		return err
	}
	fmt.Fprintln(c.stderr)

	stored := &config.Tokens{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		Expiry:       time.Now().Unix() + int64(tokens.ExpiresIn),
		Issuer:       d.Issuer,
		APIBase:      c.apiBase,
	}
	if err := config.SaveTokens(stored); err != nil {
		return fmt.Errorf("storing the token failed: %w", err)
	}
	settings, err := config.LoadSettings()
	if err != nil {
		return err
	}
	if settings.APIBase != c.apiBase {
		settings.APIBase = c.apiBase
		if err := config.SaveSettings(settings); err != nil {
			return fmt.Errorf("saving the deployment URL failed: %w", err)
		}
	}

	// Verify the token actually maps to a live user before claiming
	// success: the platform re-checks the live account on every call,
	// so a token minted for a since-deactivated user must not look
	// like a working login.
	api := platform.New(c.apiBase, &auth.Bearer{Token: stored.AccessToken})
	who, err := api.Whoami(ctx)
	if err != nil {
		return fmt.Errorf("signed in, but the platform rejected the token: %w", err)
	}
	fmt.Fprintf(c.stderr, "\nSigned in to %s (user %v, account %v)\n",
		c.apiBase, who["user_id"], who["account_id"])
	fmt.Fprintln(c.stderr, "Next: zq creds add identity --project <project> — or just ask your agent.")
	return nil
}

// cmdLogout revokes (best-effort) and clears the stored token. A
// corrupt credentials file must not trap the user: logout always
// clears, whatever LoadTokens thinks of the contents.
func cmdLogout(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq logout", flag.ContinueOnError)
	if err := c.parse(fs); err != nil {
		return err
	}
	ctx := c.ctx
	tokens, err := config.LoadTokens()
	if err != nil {
		if clearErr := config.ClearTokens(); clearErr != nil {
			return clearErr
		}
		fmt.Fprintln(c.stderr, "The stored login was unreadable; it has been removed. Run `zq login` to sign in again.")
		return nil
	}
	if tokens == nil {
		fmt.Fprintln(c.stderr, "Not signed in.")
		return nil
	}
	// Best-effort revocation at the realm. Revocation here is hygiene:
	// the real control is the platform itself, which re-checks the
	// live account on every request.
	if tokens.RefreshToken != "" && tokens.Issuer != "" {
		client := platform.HTTP()
		if d, derr := auth.Discover(ctx, client, tokens.APIBase); derr == nil {
			auth.Revoke(ctx, client, d, tokens.RefreshToken)
		}
	}
	if err := config.ClearTokens(); err != nil {
		return err
	}
	fmt.Fprintln(c.stderr, "Signed out; the stored token was removed.")
	return nil
}

// cmdWhoami verifies the credentials the same way CI would.
func cmdWhoami(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq whoami", flag.ContinueOnError)
	if err := c.parse(fs); err != nil {
		return err
	}
	client, err := resolveClient(c.ctx, c.apiBase, c.tokenFlag, c.stderr)
	if err != nil {
		return err
	}
	who, err := client.Whoami(c.ctx)
	if err != nil {
		return err
	}
	// This is a data command (no secret ever flows through it), so
	// stdout carries the summary like every other machine-readable output.
	_, err = fmt.Fprintf(c.stdout, "account_id: %v\nuser_id: %v\nrole: %v\n",
		who["account_id"], who["user_id"], who["role"])
	return err
}

// openBrowserFn is the browser-opener indirection tests stub out.
var openBrowserFn = openBrowser

// openBrowser is best-effort: false when no opener exists or it fails
// (the printed URL is always enough to finish the flow).
func openBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	go func() { _ = cmd.Wait() }()
	return true
}
