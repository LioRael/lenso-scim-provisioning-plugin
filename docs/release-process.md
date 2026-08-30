# Release process

This repository publishes crates in dependency order:

1. `lenso-capability-scim-directory`
2. `lenso-scim-provisioning-postgres-plugin`

Publication is manual-only from reviewed `main` through
`.github/workflows/release-plz.yml`. A push may refresh a Release-plz PR but
does not publish. Live publication requires `main`, `live=true`, and literal
confirmation `publish`.

## Trusted Publisher

Configure one crates.io Trusted Publisher per crate:

- owner: `LioRael`
- repository: `lenso-scim-provisioning-plugin`
- workflow: `release-plz.yml`
- environment: unset

The confirmed live job alone receives `id-token: write`; there is no Cargo
registry token fallback. Trusted Publishing cannot allocate a new crate name,
so allocate each unowned name once with a temporary narrowly scoped token,
revoke it, then use OIDC only.

## Required evidence

Run every command in the README Validation section and the PostgreSQL
acceptance command. Confirm the lockfile contains the exact Auth, Organization,
Access Control, Secrets, Web, Postgres Kit, and protocol revisions pinned by
`Cargo.toml`.
