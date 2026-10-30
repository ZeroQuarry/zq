package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ZeroQuarry/zq/internal/cookies"
	"github.com/ZeroQuarry/zq/internal/credfile"
	"github.com/ZeroQuarry/zq/internal/platform"
)

// identityRoles are the roles a stored identity can play in a scan
// (which side of the target the credential represents).
var identityRoles = []string{"primary", "victim", "attacker", "observer"}

func runCreds(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		credsUsage(stderr)
		return 2
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			credsUsage(stderr)
			return 2
		}
		switch args[1] {
		case "identity":
			return runCommand(ctx, args[2:], stdin, stdout, stderr, cmdCredsAddIdentity)
		case "git":
			return runCommand(ctx, args[2:], stdin, stdout, stderr, cmdCredsAddGit)
		default:
			fmt.Fprintf(stderr, "zq: unknown credential kind %q (want identity or git)\n\n", args[1])
			credsUsage(stderr)
			return 2
		}
	case "list":
		if len(args) < 2 {
			credsUsage(stderr)
			return 2
		}
		switch args[1] {
		case "identity":
			return runCommand(ctx, args[2:], stdin, stdout, stderr, cmdCredsListIdentities)
		case "git":
			return runCommand(ctx, args[2:], stdin, stdout, stderr, cmdCredsListGit)
		default:
			fmt.Fprintf(stderr, "zq: unknown credential kind %q (want identity or git)\n\n", args[1])
			credsUsage(stderr)
			return 2
		}
	case "help", "-h", "--help":
		credsUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "zq: unknown creds command %q\n\n", args[0])
		credsUsage(stderr)
		return 2
	}
}

func credsUsage(w io.Writer) {
	fmt.Fprint(w, `Manage scan credentials (values in, references out — never stored locally).

Usage:
  zq creds add identity [flags]    upload auth material → auth_identity_id
  zq creds add git [flags]         upload git credential → git_credential_id
  zq creds list identity [--project P]
  zq creds list git

Add flags:
  --project ID|NAME   target project for the identity library
  --label LABEL       display label (prompted when omitted)
  --role ROLE         primary | victim | attacker | observer (default primary)
  --kind KIND         with --from-file: cookies | headers | auth
                      (default: sniff the file's shape)
  --from-file PATH    read values from a user-selected file (cookies in
                      any export shape, "Header: value" lines, a PEM
                      private key, or a full auth JSON object)

Git add flags:
  --type https|ssh    credential type (default: sniff the file / prompt)
  --host HOST         git host (github.com, gitlab.example.com, ...)
  --username USER     the credential's username
  --name NAME         display name (prompted when omitted)
  --from-file PATH    token file (https) or PEM private key (ssh)
  --known-hosts PATH  known_hosts file to store with an ssh credential

Values are read from hidden prompts or --from-file only — never
command-line flags (flags leak via shell history and `+"`ps`"+`).
Output: the reference id, nothing else. Prompts go to stderr.
`)
}

// --- creds add identity -------------------------------------------------

type addIdentityOpts struct {
	project  string
	label    string
	role     string
	kind     string
	fromFile string
}

func cmdCredsAddIdentity(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq creds add identity", flag.ContinueOnError)
	opts := &addIdentityOpts{}
	fs.StringVar(&opts.project, "project", "", "project id or name (required unless the account has exactly one)")
	fs.StringVar(&opts.label, "label", "", "display label for the identity")
	fs.StringVar(&opts.role, "role", "primary", "identity role: primary|victim|attacker|observer")
	fs.StringVar(&opts.kind, "kind", "", "with --from-file: cookies | headers | auth (default: sniff)")
	fs.StringVar(&opts.fromFile, "from-file", "", "read values from this file instead of prompting")
	if err := c.parse(fs); err != nil {
		return err
	}

	// Everything cheap and non-secret happens FIRST — local flag
	// validation, authentication, project resolution — so a typo'd
	// flag or a dead login never costs the user a typed secret.
	role := strings.ToLower(strings.TrimSpace(opts.role))
	if !validRole(role) {
		return failf("invalid --role %q (want one of: %s)", opts.role, strings.Join(identityRoles, ", "))
	}
	if err := validateIdentityKind(opts.kind, opts.fromFile != ""); err != nil {
		return err
	}

	api, err := resolveClient(c.ctx, c.apiBase, c.stderr)
	if err != nil {
		return err
	}
	project, err := c.resolveProject(api, opts.project)
	if err != nil {
		return err
	}

	// --- credential material: file or hidden prompt ---------------------
	authMaterial, kind, err := c.gatherIdentityAuth(opts)
	if err != nil {
		return err
	}
	if !authMaterial.HasCredential() {
		return failf("no credential material provided — nothing was uploaded")
	}

	label := opts.label
	if label == "" {
		label = defaultIdentityLabel(kind)
		if c.streams.IsTerminal() {
			if label, err = c.streams.Line(fmt.Sprintf("Label for this identity (enter = %q)", label)); err != nil {
				return err
			}
			if label == "" {
				label = defaultIdentityLabel(kind)
			}
		}
	}

	id, err := api.AddIdentity(c.ctx, project.ID, label, role, authMaterial)
	if err != nil {
		return err
	}
	// THE output: the reference id, nothing else. The agent passes
	// this as auth_identity_id when creating the scan; the value never
	// entered model context — the platform expands the reference
	// itself, where the scan runs.
	fmt.Fprintln(c.stdout, id)
	fmt.Fprintf(c.stderr, "Stored %q in project %s. Use it as auth_identity_id.\n", label, project.ID)
	return nil
}

// gatherIdentityAuth collects credential material from --from-file or
// the hidden prompts, returning it plus the kind that produced it.
func (c *cmdCtx) gatherIdentityAuth(opts *addIdentityOpts) (*platform.Auth, string, error) {
	if opts.fromFile != "" {
		raw, err := credfile.ReadFile(opts.fromFile)
		if err != nil {
			return nil, "", err
		}
		material, err := credfile.IdentityAuthKinded(raw, opts.kind)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", opts.fromFile, err)
		}
		kind := opts.kind
		if kind == "" {
			kind = "file"
		}
		return material, kind, nil
	}

	s := c.streams
	kind := opts.kind
	if kind == "" || kind == "auto" {
		idx, err := s.Choose("What kind of credential is this?", []string{
			"Cookies (a browser session paste)",
			"Headers (an API key / bearer token)",
			"HTTP Basic (username + password)",
			"A form login the platform performs at scan start",
		})
		if err != nil {
			return nil, "", err
		}
		kind = []string{"cookies", "headers", "basic", "form"}[idx]
	}
	material := &platform.Auth{}
	switch kind {
	case "cookies":
		paste, err := s.Secret("Paste the cookies (DevTools copy, document.cookie, k=v lines)")
		if err != nil {
			return nil, "", err
		}
		material.Cookies = cookies.Normalize(paste)
		if material.Cookies == "" {
			return nil, "", failf("no cookie material in that paste")
		}
	case "headers":
		paste, err := s.Secret("Paste the headers, one `Name: value` line each")
		if err != nil {
			return nil, "", err
		}
		parsed, err := credfile.IdentityAuthKinded([]byte(paste), "headers")
		if err != nil {
			return nil, "", err
		}
		material.Headers = parsed.Headers
	case "basic":
		username, err := s.Line("Basic auth username")
		if err != nil {
			return nil, "", err
		}
		password, err := s.Secret("Basic auth password")
		if err != nil {
			return nil, "", err
		}
		material.BasicAuth = &platform.BasicAuth{Username: username, Password: password}
	case "form":
		fl, err := c.promptFormLogin()
		if err != nil {
			return nil, "", err
		}
		material.FormLogin = fl
	default:
		return nil, "", failf("unknown --kind %q (want cookies, headers, basic, or form)", kind)
	}
	return material, kind, nil
}

// validateIdentityKind checks --kind up front, with the accepted set
// spelled out per input path so the flag behaves identically whichever
// way the values arrive.
func validateIdentityKind(kind string, fromFile bool) error {
	switch kind {
	case "", "auto":
		return nil
	case "cookies", "headers", "auth":
		return nil
	case "basic", "form":
		if fromFile {
			return failf("--kind %q applies to the interactive prompt; with --from-file, "+
				"express a %s login as a full auth JSON object (or drop --kind to sniff)", kind, kind)
		}
		return nil
	default:
		return failf("unknown --kind %q (want cookies, headers, basic, form, or auth)", kind)
	}
}

// promptFormLogin walks the fields of a login the platform performs
// itself at scan start: the form POST (or JSON API login), the field
// names, and — for API logins — where the response carries a session
// token and which header it becomes.
func (c *cmdCtx) promptFormLogin() (*platform.FormLogin, error) {
	s := c.streams
	fl := &platform.FormLogin{}
	var err error
	if fl.URL, err = s.Line("Login URL (POST target)"); err != nil {
		return nil, err
	}
	if fl.UsernameField, err = s.Line("Username field name (enter = username)"); err != nil {
		return nil, err
	}
	if fl.UsernameField == "" {
		fl.UsernameField = "username"
	}
	if fl.Username, err = s.Line("Username"); err != nil {
		return nil, err
	}
	if fl.Password, err = s.Secret("Password"); err != nil {
		return nil, err
	}
	if fl.PasswordField, err = s.Line("Password field name (enter = password)"); err != nil {
		return nil, err
	}
	if fl.PasswordField == "" {
		fl.PasswordField = "password"
	}
	idx, err := s.Choose("Request encoding?", []string{"form (default)", "json"})
	if err != nil {
		return nil, err
	}
	if idx == 1 {
		fl.Encoding = "json"
	}
	// API logins: a session-token path in the response and the header
	// it becomes (a JSON login whose body carries the token).
	tokenPath, err := s.Line("Response token path for API logins (enter = none, e.g. data.access_token)")
	if err != nil {
		return nil, err
	}
	if tokenPath != "" {
		fl.TokenPath = tokenPath
		tokenHeader, err := s.Line("Token header (enter = Authorization: Bearer {token})")
		if err != nil {
			return nil, err
		}
		if tokenHeader == "" {
			tokenHeader = "Authorization: Bearer {token}"
		}
		fl.TokenHeader = tokenHeader
	}
	return fl, nil
}

func validRole(role string) bool {
	for _, r := range identityRoles {
		if r == role {
			return true
		}
	}
	return false
}

func defaultIdentityLabel(kind string) string {
	switch kind {
	case "cookies":
		return "Session cookies"
	case "headers":
		return "API headers"
	case "basic":
		return "Basic auth"
	case "form":
		return "Form login"
	default:
		return "CLI-imported credential"
	}
}

// --- project resolution -------------------------------------------------

// resolveProject maps a --project flag (id or name) or the account's
// project list onto one project.
func (c *cmdCtx) resolveProject(api *platform.Client, flagValue string) (*platform.Project, error) {
	projects, err := api.Projects(c.ctx)
	if err != nil {
		return nil, err
	}
	if len(projects) == 0 {
		return nil, failf("this account has no projects — create one in the ZeroQuarry web app first")
	}
	if flagValue != "" {
		for i := range projects {
			if projects[i].ID == flagValue || strings.EqualFold(projects[i].Name, flagValue) {
				return &projects[i], nil
			}
		}
		names := make([]string, len(projects))
		for i := range projects {
			names[i] = projects[i].Name
		}
		return nil, failf("no project matches %q — available: %s", flagValue, strings.Join(names, ", "))
	}
	if len(projects) == 1 {
		return &projects[0], nil
	}
	names := make([]string, len(projects))
	for i := range projects {
		names[i] = projects[i].Name + " (" + projects[i].ID + ")"
	}
	idx, err := c.streams.Choose("Which project should hold this identity?", names)
	if err != nil {
		return nil, err
	}
	return &projects[idx], nil
}

// --- creds add git ------------------------------------------------------

type addGitOpts struct {
	name       string
	authType   string
	host       string
	username   string
	fromFile   string
	knownHosts string
}

func cmdCredsAddGit(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq creds add git", flag.ContinueOnError)
	opts := &addGitOpts{}
	fs.StringVar(&opts.name, "name", "", "display name for the credential")
	fs.StringVar(&opts.authType, "type", "", "https | ssh (default: sniff --from-file, else prompt)")
	fs.StringVar(&opts.host, "host", "", "git host (e.g. github.com, git.corp.example.com)")
	fs.StringVar(&opts.username, "username", "", "credential username (e.g. x-oauth-basic, git)")
	fs.StringVar(&opts.fromFile, "from-file", "", "token file (https) or PEM private key (ssh)")
	fs.StringVar(&opts.knownHosts, "known-hosts", "", "known_hosts file to store with an ssh credential")
	if err := c.parse(fs); err != nil {
		return err
	}

	// Everything cheap and non-secret comes first (same rule as
	// identity): flag validation, authentication, host, username —
	// THEN the secret.
	requestedType := strings.ToLower(strings.TrimSpace(opts.authType))
	if requestedType != "" && requestedType != "https" && requestedType != "ssh" {
		return failf("invalid --type %q (want https or ssh)", opts.authType)
	}
	if opts.knownHosts != "" && requestedType == "https" {
		return failf("--known-hosts applies only to SSH credentials")
	}

	api, err := resolveClient(c.ctx, c.apiBase, c.stderr)
	if err != nil {
		return err
	}

	// The host and username are metadata (visible in list views), so a
	// non-interactive run must never let stdin fill them by accident:
	// the piped secret would become the host, uploaded in plaintext
	// metadata, and the credential would be orphaned. Require flags.
	s := c.streams
	host := credfile.NormalizeGitHost(opts.host)
	if host == "" {
		if !s.IsTerminal() {
			return failf("no --host given — pass it explicitly for non-interactive runs")
		}
		if host, err = s.Line("Git host (e.g. github.com or git.corp.example.com)"); err != nil {
			return err
		}
		host = credfile.NormalizeGitHost(host)
	}
	if host == "" {
		return failf("a git host is required")
	}
	username := strings.TrimSpace(opts.username)
	if username == "" {
		if !s.IsTerminal() {
			return failf("no --username given — pass it explicitly for non-interactive runs")
		}
		if username, err = s.Line("Username (e.g. x-oauth-basic for tokens, git for SSH keys)"); err != nil {
			return err
		}
		username = strings.TrimSpace(username)
	}

	secret, authType, err := c.gatherGitSecret(opts, requestedType)
	if err != nil {
		return err
	}
	if strings.TrimSpace(secret) == "" {
		return failf("no credential material provided — nothing was uploaded")
	}

	knownHosts := ""
	switch {
	case opts.knownHosts != "" && authType != "ssh":
		return failf("--known-hosts applies only to SSH credentials (this one is %s)", authType)
	case opts.knownHosts != "":
		var raw []byte
		if raw, err = credfile.ReadFile(opts.knownHosts); err != nil {
			return fmt.Errorf("known-hosts: %w", err)
		}
		knownHosts = strings.TrimSpace(string(raw))
	}

	name := opts.name
	if name == "" {
		name = fmt.Sprintf("%s (%s)", host, authType)
		if s.IsTerminal() {
			if name, err = s.Line(fmt.Sprintf("Name for this credential (enter = %q)", name)); err != nil {
				return err
			}
			if name == "" {
				name = fmt.Sprintf("%s (%s)", host, authType)
			}
		}
	}

	id, err := api.AddGitCredential(c.ctx, name, authType, host, username, secret, knownHosts)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, id)
	fmt.Fprintf(c.stderr, "Stored %q (%s). Use it as git_credential_id.\n", name, authType)
	return nil
}

// gatherGitSecret resolves the git secret (token or private key).
// authType arrives pre-validated ("" means sniff or prompt); the
// returned value is the type the secret implies.
func (c *cmdCtx) gatherGitSecret(opts *addGitOpts, authType string) (secret, resolvedType string, err error) {
	if opts.fromFile != "" {
		raw, err := credfile.ReadFile(opts.fromFile)
		if err != nil {
			return "", "", err
		}
		if authType == "" {
			if credfile.LooksLikePEM(raw) {
				authType = "ssh"
			} else {
				authType = "https"
			}
		}
		if authType == "ssh" && !credfile.LooksLikePEM(raw) {
			return "", "", fmt.Errorf("%s does not look like a PEM private key", opts.fromFile)
		}
		return strings.TrimRight(string(raw), "\n\r"), authType, nil
	}

	s := c.streams
	if authType == "" {
		idx, err := s.Choose("What kind of Git credential?", []string{
			"HTTPS — a personal access token / app token",
			"SSH — a private deploy key (a --from-file PEM is easier)",
		})
		if err != nil {
			return "", "", err
		}
		authType = []string{"https", "ssh"}[idx]
	}
	if authType == "https" {
		secret, err = s.Secret("Paste the access token")
		return secret, authType, err
	}
	secret, err = s.SecretMultiline("Paste the private key")
	if err != nil {
		return "", "", err
	}
	if !credfile.LooksLikePEM([]byte(secret)) {
		return "", "", failf("that doesn't look like a PEM private key (expected -----BEGIN ... PRIVATE KEY-----)")
	}
	return secret, authType, nil
}

// --- creds list ---------------------------------------------------------

func cmdCredsListIdentities(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq creds list identity", flag.ContinueOnError)
	projectFlag := ""
	fs.StringVar(&projectFlag, "project", "", "project id or name")
	if err := c.parse(fs); err != nil {
		return err
	}
	api, err := resolveClient(c.ctx, c.apiBase, c.stderr)
	if err != nil {
		return err
	}
	project, err := c.resolveProject(api, projectFlag)
	if err != nil {
		return err
	}
	refs, err := api.IdentityRefs(c.ctx, project.ID)
	if err != nil {
		return err
	}
	// Metadata only: the list payload is defined to carry shapes and
	// names, never values — so this output cannot leak by construction.
	fmt.Fprintf(c.stdout, "%s\t%-8s\t%-24s\t%s\n", "ID", "ROLE", "LABEL", "KIND")
	for _, r := range refs {
		fmt.Fprintf(c.stdout, "%s\t%-8s\t%-24s\t%s\n", r.ID, r.Role, r.Label, r.Kind)
	}
	fmt.Fprintf(c.stderr, "%d identit%s in %s\n", len(refs), plural(len(refs), "y", "ies"), project.ID)
	return nil
}

func cmdCredsListGit(c *cmdCtx) error {
	fs := flag.NewFlagSet("zq creds list git", flag.ContinueOnError)
	if err := c.parse(fs); err != nil {
		return err
	}
	api, err := resolveClient(c.ctx, c.apiBase, c.stderr)
	if err != nil {
		return err
	}
	refs, err := api.GitCredentialRefs(c.ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "%s\t%-5s\t%-24s\t%-20s\t%s\n", "ID", "TYPE", "NAME", "HOST", "USERNAME")
	for _, r := range refs {
		fmt.Fprintf(c.stdout, "%s\t%-5s\t%-24s\t%-20s\t%s\n", r.ID, r.AuthType, r.Name, r.Host, r.Username)
	}
	fmt.Fprintf(c.stderr, "%d git credential%s\n", len(refs), plural(len(refs), "", "s"))
	return nil
}

func plural(n int, singular, pluralSuffix string) string {
	if n == 1 {
		return singular
	}
	return pluralSuffix
}
