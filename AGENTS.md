# Repository instructions

- Run Cargo through `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo`.
- Keep `capability.json`, JSON Schemas, and generated Rust projections exact.
- Database migrations are operator-managed; Plugin activation must not apply DDL.
- Never log bearer credentials, email values, Actor assertions, database URLs, or secret values.
- SCIM deprovisioning is organization-local. Do not add a global Identity disable port.
