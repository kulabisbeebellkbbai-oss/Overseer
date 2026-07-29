# Overseer Key Broker

The key broker separates command authority from secret custody.

Overseer decides whether work is allowed. The broker owns provider metadata,
secret references, scoped token requests, issued grants, revocation, and audit
evidence. Raw provider secrets and raw issued tokens are not stored in SQLite or
returned by API status calls.

## Model

- Provider: a secret authority such as a static token, GitHub App, or break-glass
  master credential.
- Request: an Overseer-approved work unit asking for specific scopes and a short
  lifetime.
- Grant: an issued short-lived token written under `local-secrets/key-broker`.

Master credentials should be registered only as `break_glass` providers. Routine
work should use provider-specific scopes and short-lived grants.

## Commands

```bash
overseer record-key-provider --store state/overseer.sqlite3 \
  --provider-id github.app.overseer \
  --display-name "Overseer GitHub App" \
  --provider-kind github_app \
  --secret-ref /home/god/.local/share/overseer/secrets/github-app.pem \
  --allowed-scope contents:read \
  --allowed-scope pull_requests:write

overseer request-key-broker-token --store state/overseer.sqlite3 \
  --provider-id github.app.overseer \
  --subject "project:Overseer thread:example" \
  --scope contents:read \
  --requested-by sisko \
  --justification "inspect repository state"

overseer approve-key-broker-request --store state/overseer.sqlite3 \
  --request-id kbr.github.app.overseer... \
  --approved-by sisko \
  --approval-id approval.example

overseer issue-key-broker-token --store state/overseer.sqlite3 \
  --project-root . \
  --request-id kbr.github.app.overseer... \
  --issued-by odo
```

## GitHub App Follow-Up

The current broker implements the durable policy, storage, approval, local grant,
and audit surface. The GitHub App provider kind is present, but exchanging a
private key for a GitHub installation token still needs provider-specific
adapter work once the App ID, installation ID, and private key path are
available.

Until then, issued GitHub-App grants are internal broker proof tokens for
adapter testing, not live GitHub installation tokens.

## Security Rules

- Do not put provider private keys or PATs in the repo.
- Use restrictive permissions on any file named by `secret_ref`.
- Keep token TTL short.
- Use exact scopes instead of `*`.
- Require explicit approval for GitHub App, break-glass, or wildcard requests.
- Odo should monitor every issue, revoke, expiry, and scope denial event.
