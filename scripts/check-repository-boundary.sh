#!/usr/bin/env bash
set -euo pipefail

forbidden='lenso-platform-|lenso-module-auth|HostBuilder|HostLinkedModule|ModuleManifest|lenso module install|platform_core|platform_module'
if rg -n "$forbidden" Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo "legacy Lenso dependency or API found in SCIM source" >&2
  exit 1
fi

if rg -n 'lenso-http-auth' Cargo.toml crates; then
  echo "stale HTTP Auth dependency found in SCIM source" >&2
  exit 1
fi

if rg -n 'CREATE TABLE (identities|credentials|sessions|organizations|memberships|roles|permissions|role_bindings)' \
  crates/lenso-scim-provisioning-postgres-plugin/migrations; then
  echo "SCIM crossed Identity, Organization, or Access Control storage ownership" >&2
  exit 1
fi

if rg -n '(println!|eprintln!|dbg!|tracing::[a-z]+!)\([^\n]*(credential|email|database_url|assertion|secret)' \
  crates/lenso-scim-provisioning-postgres-plugin/src --glob '!postgres_tests.rs'; then
  echo "sensitive SCIM material reached a diagnostic macro" >&2
  exit 1
fi

if rg -n 'AccountAdmin|disable_account|global.*disable' crates --glob '!**/generated.rs'; then
  echo "SCIM must not globally disable an Identity" >&2
  exit 1
fi

if find . -name .gitkeep -print -quit | rg -q .; then
  echo ".gitkeep placeholders are not allowed in the released repository" >&2
  exit 1
fi

printf 'repository boundary is SCIM-only, authority-separated, and descriptor-first\n'
