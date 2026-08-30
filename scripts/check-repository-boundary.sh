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

required_pins=(
  b763a63adc20f1ccc9955e784c0d04c21489126b
  b4a2f53df882ae51021aa3d5922d8ee41bf97c72
  de1e1f1ec61232b13fc90a05f1cb4e3fc96ba420
  d3fa8b27c3dea470fcbf72183a7cca1fc032a117
  9572afd465ba2f952b646ec16935c0274f66c82a
  c31aa142ff59b4536e2bf3e9785ccbb5bb5c0e6a
  9769bc5dc828fd9111da6d28a4ecd5f1bb198ab4
  cd35675a191d815b690c8889756dfe859a0e4d7b
  525c1012c789e6f54c3c2fdaf8507a626c93e65f
)
for pin in "${required_pins[@]}"; do
  if ! rg -q "$pin" Cargo.toml; then
    echo "required exact Lenso dependency pin is missing: $pin" >&2
    exit 1
  fi
done

if find . -name .gitkeep -print -quit | rg -q .; then
  echo ".gitkeep placeholders are not allowed in the released repository" >&2
  exit 1
fi

printf 'repository boundary is SCIM-only, authority-separated, and descriptor-first\n'
