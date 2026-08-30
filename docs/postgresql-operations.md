# PostgreSQL operations

## Setup and upgrade

Run `ScimProvisioningOperator::setup` once for a new owned schema. Run
`ScimProvisioningOperator::upgrade` before activating a Plugin version with new
migrations. Activation performs no DDL.

The runtime role needs ordinary DML only inside this schema. Do not grant it
access to Auth, Organization, or Access Control storage.

## Backup and restore

Back up these tables together with the Postgres Kit migration ledger:

- `scim_users`
- `scim_groups`
- `scim_group_members`
- `scim_sync_receipts`
- `scim_membership_projection`
- `scim_role_projection`

Email addresses and Identity subjects are personal data. Encrypt backups,
restrict operator access, and apply the product's directory retention policy.
Command receipts and projection rows must be restored with resources because
they are part of idempotency and repair correctness.

## Repair

Invoke `repair_sync` from one exact `repair_callers` Instance with a limit from
1 through 100. Repair scans only desired/applied differences, invokes the typed
Organization/RBAC ports, verifies role state through Access Control Directory,
and marks receipts complete only after convergence.

If repair remains pending, inspect the authoritative Organization membership
and Access Control providers. Do not mutate projection flags by hand. A global
Identity disable is never part of SCIM repair.

## Acceptance test

The optional suite creates and drops only a UUID-named `scim_acceptance_*`
schema in the configured database.

```sh
LENSO_SCIM_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/postgres \
  cargo test --locked -p lenso-scim-provisioning-postgres-plugin \
  --features postgres-acceptance \
  postgres_restart_uniqueness_cas_and_receipt_acceptance -- --nocapture
```
