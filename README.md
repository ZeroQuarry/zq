# zq — the ZeroQuarry companion CLI

`zq` moves scan credentials to ZeroQuarry **without opening the web
app and without the values ever entering agent context**. It exists
because remote MCP servers cannot read local files: when your agent
needs an authenticated scan of `app.example.com` or a private repo,
*something* local has to do the upload — and that something must not
be the model.

It is the same shape as `gh auth login` or `stripe listen`: a small
local binary that performs exactly one secret-bearing step — the
user's hand moves the credential, the CLI uploads it over HTTPS, and
prints the **reference id** (`auth_identity_id` / `git_credential_id`)
your agent then uses in `create_scan`. The platform stores the secret;
the agent only ever sees the reference.

```
$ zq creds add identity --project "Main Site"
What kind of credential is this?      # prompts render on stderr
  1) Cookies (a browser session paste)
  2) Headers (an API key / bearer token)
  ...
Paste the cookies (DevTools copy, document.cookie, k=v lines) (input hidden):
Stored "Session cookies" in project proj-aaa. Use it as auth_identity_id.
ident-1234                                            # stdout: the id, nothing else
```

Then tell your agent:

> scan https://app.example.com with auth_identity_id `ident-1234`

The value never entered model context, scan logs, or an LLM provider —
the platform attaches it to requests deterministically at scan time.
That is ZeroQuarry's standing credential boundary: *the platform
attaches credentials; the model never sees them.* This CLI removes the
web app from the path without weakening the boundary.

## Install

**Homebrew** (after the first release is cut):

```sh
brew install zeroquarry/tap/zq
```

**Release binaries**: grab a checksummed tarball for darwin/linux
(amd64/arm64) from
[Releases](https://github.com/ZeroQuarry/zq/releases), verify with the
published SHA256SUMS, and drop `zq` on your `PATH`.

**From source**:

```sh
go install github.com/ZeroQuarry/zq@latest
```

## Commands

| Command | What it does |
| --- | --- |
| `zq login` | Sign in via the OAuth device flow — a URL + code on stderr, your browser does the login (Google/GitHub through the platform's IdP). Tokens stay in your user config directory (`~/.config/zq/credentials.json` on Linux, `~/Library/Application Support/zq/credentials.json` on macOS; override with `ZQ_CONFIG_DIR`), written 0600. |
| `zq logout` | Best-effort revocation, then deletes the stored token. |
| `zq whoami` | Verifies credentials the way CI would. |
| `zq creds add identity` | Upload auth material (cookies / headers / basic / form login) to a project's identity library → prints `auth_identity_id`. |
| `zq creds add git` | Upload an HTTPS token or SSH deploy key → prints `git_credential_id`. |
| `zq creds list identity\|git` | List stored references — ids, labels, kinds. Metadata only, never values. |

### Values: hidden stdin or `--from-file`, never flags

Credential values are read from **hidden prompts** (echo disabled on a
TTY; a pipe works too:
`print $SESSION | zq creds add identity --kind cookies`) or
from a **user-selected file**. Never command-line flags — flags leak
through shell history and process listings.

`--from-file` accepts the shapes people actually have lying around:

- a full auth object (`{"cookies": ..., "form_login": ...}`) — what an
  agent or power user writes verbatim; unknown keys fail loudly
- cookie exports: JSON (`[{"name": ..., "value": ...}]` or a map),
  Netscape/cookies.txt, Chrome/Firefox DevTools TSV, `k=v` lines,
  `document.cookie` strings — normalized to one canonical form
- raw request headers (`Header: value` lines, including `curl -v`
  output — only the `> ` request lines are kept; responses and
  noise are ignored)
- a PEM private key (→ SSH git credential), or a token file (→ HTTPS)

Scripted example:

```sh
print $SESSION_COOKIE | zq creds add identity \
  --project "Main Site" --label "prod session" --role primary \
  --kind cookies

zq creds add git --from-file ~/deploy_ed25519 \
  --host git.corp.example.com --username git --name "corp deploy key"
```

### Self-hosted deployments

```sh
zq login --api https://zq.corp.example.com     # persists the base URL
# or per-invocation: ZQ_URL=... / --api ...
```

### CI / headless

The static-key path is supported indefinitely:

```sh
export ZQ_KEY=zq_...
zq whoami
```

## Security properties

- **The reference-id output contract.** `zq creds add ...` writes only
  the id to stdout; prompts, progress, and errors go to stderr. Tests
  pin this byte-for-byte.
- **Values have three homes and no more**: the hidden prompt / file
  bytes, the request body on the wire (TLS), and the platform's
  encrypted store. Nothing is cached, logged, or written locally. The
  error paths quote the *server's* message and never the payload.
- **No browser-credential-store harvesting, ever**: automated
  extraction from Chrome/Safari cookie stores is infostealer-shaped —
  EDR-flagged and exactly wrong for a security vendor. User-initiated
  import of a user-selected file is the boundary, deliberately.
- **Authenticate before prompting.** The CLI never asks for a secret
  unless the invocation is signed in and ready to upload it.
- **The login is OAuth 2.1-grade**: device flow (RFC 8628) discovered
  through the platform's RFC 9728 metadata, audience-bound via RFC
  8707 `resource`, proactive refresh, best-effort revocation on
  logout. The platform re-checks your live account on every request,
  so deactivating a user there ends agent access on the next call —
  no token-revocation ceremony. (Like the MCP endpoint, the ingest
  routes must accept IdP-issued JWTs for this to hold; see
  docs/api-contract.md.)
- **The token file is `0600`**, and a looser legacy file is repaired
  on save.

## What a deployment needs

`zq` consumes a small REST surface specified in
[docs/api-contract.md](docs/api-contract.md): two ingest endpoints
(`POST /api/v1/projects/{id}/identities`,
`POST /api/v1/git-credentials`) with the same validation semantics as
the web app's credential managers, their list counterparts (metadata
shapes only), a device-flow client in the deployment's
authorization-server realm, and IdP-JWT acceptance on those routes.

**Status:** that server work is specified but not yet rolled out on
every deployment — until a deployment serves these endpoints its
uploads fail fast (the 404s name what's missing), and the path in is
a `ZQ_KEY` static key plus the web app. The document doubles as the
implementation checklist for self-hosted operators.

## Development

```sh
go test ./...     # the whole suite: parsers, flows, and leak checks
go vet ./...
go build -o zq .  # try it against a stub: see internal/cli/cli_test.go
```

Layout: `internal/auth` (device flow + token resolution), `internal/
platform` (API client + payload shapes), `internal/credfile` +
`internal/cookies` (file import + cookie normalization), `internal/
prompt` (stderr prompts, hidden input), `internal/cli` (commands),
`internal/config` (settings + 0600 token store). A repository-hygiene
test (`internal/cleanroom`) fails if internal jargon or
not-for-publication references ever creep into this tree — this
repository is meant to be read and audited end to end.

Cutting a release: push a `v*` tag; `.github/workflows/release.yml`
builds and checksums the binaries. The Homebrew formula
(`dist/zq.rb`) points at those artifacts.

## License

Apache-2.0 — see [LICENSE](LICENSE).
