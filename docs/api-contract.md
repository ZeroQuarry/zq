# The server API `zq` targets

`zq` is a thin client over a small REST surface. This document pins
that surface so the CLI and a ZeroQuarry deployment can be developed
and verified independently: deployments implement it from this
document (roll-out status is noted in the README), and self-hosted
operators can use it as an implementation checklist.

The design invariant behind the whole surface: **the user's hand moves
the secret; the model only ever sees references.** The CLI is the
local half of that handshake — values enter here (hidden prompt or a
user-selected file), travel once over TLS, and live in the platform's
encrypted store behind an id.

## Authentication

Every request carries `Authorization: Bearer <credential>`, with the
bearer accepted in two forms — the same resolution the MCP endpoint
performs, and a hard requirement for these routes (the generic API
bearer path has historically accepted only static keys, so JWT
acceptance here is an explicit work item, not a given):

1. an IdP-issued, audience-bound JWT — the token `zq login` obtains
   via the device flow below; and
2. a static `zq_` API key — the indefinitely-supported CI/headless
   path.

In both cases the server resolves the bearer to a **live** user and
re-checks that user's current permissions on every request. Nothing
permission-relevant may be baked into the credential: deactivating the
user or changing their role in the product must deny the next call
with no token ceremony.

Permission expectations for the new routes: creating an identity
requires project-edit permission on the target project; creating a git
credential requires the account-level git-credential entitlement (the
SSH flavor is additionally gated by the account's plan, mirroring how
scan creation treats SSH clone URLs).

## Endpoints

### Identity ingest

```
POST /api/v1/projects/{project_id}/identities
Authorization: Bearer ...
{"label": "prod session", "role": "primary",
 "auth": {"cookies": "k=v; ..."}
        | {"headers": {"Name": "value"}}
        | {"basic_auth": {"username": "...", "password": "..."}}
        | {"form_login": {...}}}

201 → {"id": "ident_<32-hex>"}   # ← the auth_identity_id zq prints
4xx → {"error": "operator-safe message"}
```

The `auth` object is the platform's standard credential shape —
exactly one or more of:

- `cookies`: the canonical `k=v; k2=v2` string (the CLI normalizes
  pastes to this form before sending);
- `headers`: a header-name → value map;
- `basic_auth`: `{username, password}`;
- `form_login`: `{url, username_field, username, password_field,
  password, extra_fields?, encoding: "form"|"json", token_path?,
  token_header?}` — a login the platform performs itself at scan
  start; `token_path`/`token_header` describe an API login whose
  response carries a session token (e.g. `token_path:
  "data.access_token"`, `token_header: "Authorization: Bearer
  {token}"`).

Server behavior:

- validate that `auth` carries at least one credential (reject with
  400 otherwise — an identity without material is meaningless);
- validate `role` ∈ `primary|victim|attacker|observer` (default
  `primary`) — the role records which side of the target the
  credential represents, so a scan can hold several identities at
  once (the operator's session, a second user, an attacker persona);
- store the material encrypted, attributable to the calling user, with
  a provenance value distinguishing CLI imports from web-app entries
  (`provenance: "cli"`), so list views can show where a credential
  came from;
- respond with only the id. Error bodies carry operator-safe messages
  (the same strings the web app flashes) and never echo request
  material — the request body is the one place credential values exist
  on the wire, so no error path may quote it.

### Git credential ingest

```
POST /api/v1/git-credentials
{"name": "corp deploy key", "auth_type": "https"|"ssh",
 "host": "gitlab.com", "username": "git",
 "secret": "<token | PEM private key>",
 "known_hosts": "…"}                    # ssh only, optional

201 → {"id": "<uuid>"}                  # ← the git_credential_id zq prints
```

Server behavior: normalize the host, store the secret (and
`known_hosts`) encrypted, enforce the SSH tier gate with a clear error
for accounts whose tier excludes SSH credentials. `host` arrives
already reduced to a bare hostname (the CLI strips scheme, path,
port, and any `user@` prefix) but the server should re-normalize
rather than trust that.

### Reference lists (metadata only, by construction)

```
GET /api/v1/projects/{project_id}/identities
  → {"identities": [{"id", "label", "role", "auth_kind",
                     "provenance", "verification_status",
                     "shape": {"cookie_count"?, "header_names"?,
                               "basic_username"?, "form_login_url"?},
                     "revoked"}]}

GET /api/v1/git-credentials
  → {"credentials": [{"id", "name", "auth_type", "host",
                      "username", "created_at"}]}
```

These are the list views behind the web app's credential managers:
shapes and names, never values. The `shape` object summarizes *which
kinds* of material an identity holds (counts, header names, scrubbed
URLs, usernames) — precisely the facts a scan brief reports, and
precisely bounded: passwords, token values, and cookie values have no
field to occupy. The CLI renders these rows as tables; there is no
value-bearing field in the payload to leak.

## Realm: the device-flow client

`zq login` is a **public client** with id `zq-cli` speaking the OAuth
2.0 Device Authorization Grant (RFC 8628). On the deployment's
authorization server (the realm that brokers Google/GitHub for MCP
clients), provision:

- client id `zq-cli`, public (no secret), **device grant enabled**,
  standard browser flow and direct grants off, no redirect URIs;
- the realm-default client scopes that put the platform's audience in
  the token (`aud`) and the verified email claim in **access tokens**
  (the token→user join maps on the verified email; it is also the
  reason the realm must never admit unverified emails);
- resource indicators configured so a requested `resource` binds the
  token audience — the CLI requests the RFC 9728 `resource` value the
  platform advertises, the same value MCP clients request.

Discovery chain the CLI walks (no configuration beyond the
deployment's existing OAuth wiring):

```
GET {api}/.well-known/oauth-protected-resource      (RFC 9728)
  → authorization_servers[0] = issuer
GET {issuer}/.well-known/openid-configuration
  → device_authorization_endpoint, token_endpoint,
    revocation_endpoint (optional)
```

A deployment without OAuth configured 404s the first hop; the CLI
prints the static-key fallback hint. Scope requested:
`openid email profile`.

## Acceptance checks

```sh
# 1. Discovery resolves through the CLI's chain:
curl -s https://api.example.com/.well-known/oauth-protected-resource | jq .
#    expect: resource == the platform's audience,
#            authorization_servers == [issuer]

# 2. The device grant is live for zq-cli:
curl -s -X POST "$DEVICE_ENDPOINT" \
  -d client_id=zq-cli -d 'scope=openid email profile' | jq .verification_uri

# 3. End-to-end: zq login → zq whoami → paste cookies through
#    zq creds add identity → create a scan with auth_identity_id →
#    the scan authenticates, and its logs carry no values.

# 4. Live-account behavior: deactivate the test user in the product;
#    the next zq call is denied with no token-revocation ceremony.
```

## Non-goals

- No tool arguments, prompts, or log lines anywhere in the platform
  accept credential values from the model. Scan credentials are
  attached by the platform at scan time; the model — and the agent
  transcripts it feeds — only ever carries reference ids.
- No local secret storage or sync in the CLI: courier, not vault.
- No browser-credential-store harvesting. Automated extraction from
  Chrome/Safari stores is infostealer-shaped; user-initiated import of
  a user-selected file is the boundary, deliberately.
