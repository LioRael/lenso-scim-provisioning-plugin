#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  flags+=(--allow-dirty)
fi

for manifest in crates/*/Cargo.toml; do
  rg -qx 'publish = true' "$manifest" || {
    printf '%s is not explicitly publishable\n' "$manifest" >&2
    exit 1
  }
done

"$cargo_bin" package --quiet "${flags[@]}" -p lenso-capability-scim-directory
"$cargo_bin" package --quiet "${flags[@]}" --no-verify \
  -p lenso-scim-provisioning-postgres-plugin \
  --config 'patch.crates-io.lenso-capability-scim-directory.path="crates/lenso-capability-scim-directory"'

printf 'public SCIM Provisioning package archives are valid\n'
