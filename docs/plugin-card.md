# Plugin card: PostgreSQL SCIM Provisioning

## Job

Expose an organization-local SCIM directory that maps external users and groups
onto existing Lenso Identity, Organization membership, and RBAC providers.

## Owns

- SCIM user and group representations, member links, versions, and timestamps;
- group-to-role mapping intent;
- caller/operation/idempotency command receipts;
- desired/applied membership and role projections plus bounded repair state;
- SCIM HTTP discovery, resource routing, filters, PATCH lowering, Error bodies,
  and ETags.

## Does not own

- global Identity status or credential verification;
- organizations or authoritative membership;
- roles, permissions, policy evaluation, or authoritative role bindings;
- HTTP ingress/TLS/rate limiting;
- a cross-organization SCIM directory.

## Required typed ports

- `lenso.secrets@1`
- `lenso.auth@1` through `lenso-auth-sdk` 0.2.1
- `lenso.identity-directory@1` descriptor 2.0.0
- `lenso.organization-membership-admin@1`
- `lenso.access-control-admin@1`
- `lenso.access-control-directory@1`

## Failure policy

Local SCIM state commits before downstream convergence. Known downstream
rejection or unavailable convergence remains `pending`; repair processes only
desired/applied differences. Runtime failures stay runtime failures. Deleting a
user removes only organization-local membership and mapped RBAC bindings; it
never disables the global Identity.
