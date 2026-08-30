# Lenso SCIM Provisioning Plugin

Add an organization-scoped SCIM 2.0 directory to a Lenso App while keeping
Identity, Organization membership, and RBAC authority in their independent
Plugins. The implementation owns SCIM resources and durable desired/applied
projections; it synchronizes through typed Capability ports.

## Capabilities

| Capability | Operations | Intended caller |
| --- | --- | --- |
| `lenso.scim-directory@1` | Users and Groups CRUD/list/PATCH plus `repair_sync` | exact internal directory and repair Instances |
| `lenso.http.endpoint@1` | SCIM discovery and `/scim/v2/Users` / `/scim/v2/Groups` routes | exact HTTP ingress Instances with bearer credentials |

The implementation Plugin is `lenso.scim-provisioning.postgres`, with root
slot `scim`. Both provided contracts are linked native Rust; the SCIM Directory
contract is descriptor-first, portable, and uses a checked generated projection.

## Configuration

```json
{
  "schema": "scim_directory",
  "database_url_secret": "scim/database-url",
  "organization_id": "org_acme",
  "identity_provider": "scim",
  "directory_callers": ["app.scim-admin"],
  "repair_callers": ["worker.scim-repair"],
  "http_callers": ["web.scim-ingress"],
  "accepted_actor_kinds": ["service_account"],
  "required_organization_claim": "organization_id",
  "max_page_size": 100,
  "max_group_members": 10000
}
```

Configuration is immutable for one resolved Generation. Caller lists contain
exact Instance keys, not prefixes. HTTP requests are accepted only when the
selected credential uses the Bearer scheme, Auth returns a `service_account`,
and its `organization_id` claim exactly equals the configured organization.
Authentication uses `lenso-auth-sdk` 0.2.1 directly; this repository does not
use the obsolete `lenso-http-auth` adapter.

Mutations use `Idempotency-Key` when present, otherwise the ingress
`request_id`. PUT, PATCH, and DELETE require `If-Match`. Responses expose weak
ETags derived from monotonic resource versions. Supported filters are bounded,
exact `eq` expressions over `userName`, `externalId`, or `displayName`.

## Ownership and synchronization

- Users own SCIM `externalId`, `userName`, `displayName`, emails, active state,
  subject link, version, timestamps, and sync state.
- Groups own display name, external ID, member links, optional RBAC role ID,
  version, timestamps, and sync state.
- Every downstream membership or role binding has durable desired/applied
  projection state. A local commit may return `sync_status=pending`; bounded
  `repair_sync` retries only the unfinished projection.
- Command receipts are scoped by caller, operation, and idempotency key and
  retain request hashes and stable results.

Creating a user calls `lenso.identity-directory@1` to ensure the subject.
Activating/deactivating the SCIM user adds/removes only the configured
organization membership through `lenso.organization-membership-admin@1`.
Deleting or deactivating a SCIM user never globally disables that Identity.

A Group role mapping assigns/revokes an organization-scoped binding through
`lenso.access-control-admin@1`; convergence is read back through
`lenso.access-control-directory@1`. The Plugin does not create roles or own
permissions.

## PostgreSQL setup

DDL is operator-managed. Activation resolves the database URL through
`lenso.secrets@1` and validates the existing migration ledger.

```rust,no_run
use lenso_scim_provisioning_postgres_plugin::ScimProvisioningOperator;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
ScimProvisioningOperator::setup(
    "postgres://postgres@127.0.0.1:5432/app",
    "scim_directory",
).await?;
# Ok(())
# }
```

See `docs/postgresql-operations.md` for upgrade, backup, and repair procedures.

## Validation

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
lenso-contract-codegen workspace check --manifest-path Cargo.toml
./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```
