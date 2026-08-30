#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"

metadata="$($cargo_bin metadata --locked --no-deps --format-version=1)"
repository_root="$(git rev-parse --show-toplevel)"
for package in lenso-capability-scim-directory lenso-scim-provisioning-postgres-plugin; do
  publish="$(jq -r --arg package "$package" '.packages[] | select(.name == $package) | .publish == null or (.publish | length > 0)' <<<"$metadata")"
  if [[ "$publish" != "true" ]]; then
    printf '%s is not public\n' "$package" >&2
    exit 1
  fi
done

required_source_set=(
  crates/lenso-capability-scim-directory/build.rs
  crates/lenso-capability-scim-directory/capability.json
  crates/lenso-capability-scim-directory/schemas/user-write-request.schema.json
  crates/lenso-capability-scim-directory/src/generated.rs
  crates/lenso-capability-scim-directory/src/lib.rs
  crates/lenso-scim-provisioning-postgres-plugin/configuration.schema.json
  crates/lenso-scim-provisioning-postgres-plugin/migrations/001_create_scim_directory.sql
  crates/lenso-scim-provisioning-postgres-plugin/src/lib.rs
  crates/lenso-scim-provisioning-postgres-plugin/src/http.rs
)
for source in "${required_source_set[@]}"; do
  if [[ ! -f "$repository_root/$source" ]]; then
    printf 'required package source is missing: %s\n' "$source" >&2
    exit 1
  fi
done

capability_manifest="$repository_root/crates/lenso-capability-scim-directory/Cargo.toml"
plugin_manifest="$repository_root/crates/lenso-scim-provisioning-postgres-plugin/Cargo.toml"
for packaged_asset in '"capability.json"' '"schemas/*.json"' '"src/*.rs"'; do
  rg --fixed-strings --quiet "$packaged_asset" "$capability_manifest"
done
for packaged_asset in '"configuration.schema.json"' '"migrations/*.sql"' '"src/*.rs"'; do
  rg --fixed-strings --quiet "$packaged_asset" "$plugin_manifest"
done

printf 'public SCIM package metadata and source sets are valid\n'
if [[ "${LENSO_RUN_PACKAGE_SMOKE:-0}" != "1" ]]; then
  printf 'full cargo package smoke skipped; set LENSO_RUN_PACKAGE_SMOKE=1 when registry access is available\n'
  exit 0
fi

package_flags=(--locked)
plugin_flags=()
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
  plugin_flags+=(--allow-dirty)
fi

target_directory="$(jq -r '.target_directory' <<<"$metadata")"
plugin_version="$(jq -r '.packages[] | select(.name == "lenso-scim-provisioning-postgres-plugin") | .version' <<<"$metadata")"
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-scim-package.XXXXXX")"
trap 'rm -r "$verification_root"' EXIT

checkout_exact_repository() {
  local environment_variable="$1"
  local repository_url="$2"
  local revision="$3"
  local checkout_name="$4"
  local configured="${!environment_variable:-}"
  local checkout
  if [[ -n "$configured" ]]; then
    local source_root
    source_root="$(git -C "$configured" rev-parse --show-toplevel)"
    if [[ "$(git -C "$source_root" rev-parse HEAD)" == "$revision" ]]; then
      checkout="$source_root"
    else
      checkout="$verification_root/$checkout_name"
      git clone --quiet --shared --no-checkout "$source_root" "$checkout"
      git -C "$checkout" checkout --quiet --detach "$revision"
    fi
  else
    checkout="$verification_root/$checkout_name"
    git clone --quiet --filter=blob:none --no-checkout "$repository_url" "$checkout"
    git -C "$checkout" checkout --quiet --detach "$revision"
  fi
  local actual_revision
  actual_revision="$(git -C "$checkout" rev-parse HEAD)"
  if [[ "$actual_revision" != "$revision" ]]; then
    printf '%s must resolve to %s, got %s\n' "$environment_variable" "$revision" "$actual_revision" >&2
    return 1
  fi
  printf '%s\n' "$checkout"
}

runtime_root="$(checkout_exact_repository LENSO_RUNTIME_REPOSITORY https://github.com/LioRael/lenso-runtime-rust b763a63adc20f1ccc9955e784c0d04c21489126b runtime)"
auth_root="$(checkout_exact_repository LENSO_AUTH_REPOSITORY https://github.com/LioRael/lenso-auth-plugin b4a2f53df882ae51021aa3d5922d8ee41bf97c72 auth)"
access_root="$(checkout_exact_repository LENSO_ACCESS_CONTROL_REPOSITORY https://github.com/LioRael/lenso-access-control-plugin de1e1f1ec61232b13fc90a05f1cb4e3fc96ba420 access-control)"
web_root="$(checkout_exact_repository LENSO_WEB_REPOSITORY https://github.com/LioRael/lenso-web d3fa8b27c3dea470fcbf72183a7cca1fc032a117 web)"
organization_root="$(checkout_exact_repository LENSO_ORGANIZATION_REPOSITORY https://github.com/LioRael/lenso-organization-plugin 9572afd465ba2f952b646ec16935c0274f66c82a organization)"
secrets_root="$(checkout_exact_repository LENSO_SECRETS_REPOSITORY https://github.com/LioRael/lenso-secrets-plugin c31aa142ff59b4536e2bf3e9785ccbb5bb5c0e6a secrets)"
lenso_root="$(checkout_exact_repository LENSO_KERNEL_REPOSITORY https://github.com/LioRael/lenso cd35675a191d815b690c8889756dfe859a0e4d7b kernel)"
postgres_root="$(checkout_exact_repository LENSO_POSTGRES_KIT_REPOSITORY https://github.com/LioRael/lenso-postgres-kit 525c1012c789e6f54c3c2fdaf8507a626c93e65f postgres-kit)"

source_patches=(
  --config "patch.crates-io.lenso-capability-scim-directory.path=\"$repository_root/crates/lenso-capability-scim-directory\""
  --config "patch.crates-io.lenso.path=\"$runtime_root/crates/lenso\""
  --config "patch.crates-io.lenso-auth-sdk.path=\"$auth_root/crates/lenso-auth-sdk\""
  --config "patch.crates-io.lenso-capability-auth.path=\"$auth_root/crates/lenso-capability-auth\""
  --config "patch.crates-io.lenso-capability-identity-directory.path=\"$auth_root/crates/lenso-capability-identity-directory\""
  --config "patch.crates-io.lenso-capability-access-control-admin.path=\"$access_root/crates/lenso-capability-access-control-admin\""
  --config "patch.crates-io.lenso-capability-access-control-directory.path=\"$access_root/crates/lenso-capability-access-control-directory\""
  --config "patch.crates-io.lenso-capability-http-endpoint.path=\"$web_root/crates/lenso-capability-http-endpoint\""
  --config "patch.crates-io.lenso-capability-organization-membership-admin.path=\"$organization_root/crates/lenso-capability-organization-membership-admin\""
  --config "patch.crates-io.lenso-capability-secrets.path=\"$secrets_root/crates/lenso-capability-secrets\""
  --config "patch.crates-io.lenso-kernel.path=\"$lenso_root/crates/lenso-kernel\""
  --config "patch.crates-io.lenso-postgres-kit.path=\"$postgres_root\""
)

"$cargo_bin" package --quiet "${package_flags[@]}" -p lenso-capability-scim-directory
"$cargo_bin" "${source_patches[@]}" package --quiet "${plugin_flags[@]}" --no-verify -p lenso-scim-provisioning-postgres-plugin

archive="$target_directory/package/lenso-scim-provisioning-postgres-plugin-$plugin_version.crate"
tar -xzf "$archive" -C "$verification_root"
package="$verification_root/lenso-scim-provisioning-postgres-plugin-$plugin_version"
test -f "$package/configuration.schema.json"
test -f "$package/migrations/001_create_scim_directory.sql"
test -f "$package/src/lib.rs"
printf 'public SCIM packages and required runtime assets are present\n'
