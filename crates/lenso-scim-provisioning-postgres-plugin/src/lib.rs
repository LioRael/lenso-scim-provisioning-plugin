//! Organization-scoped SCIM directory, HTTP surface, and durable sync repair.

#![allow(clippy::too_many_lines, clippy::wildcard_imports)]

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::{
    ActivateContext, DeactivateContext, Lifecycle, PluginError, PluginResult, Port, provides,
};
use lenso_auth_sdk::{AuthOutcome, CredentialEvidence, authenticate_request, decode_auth_response};
use lenso_capability_access_control_admin as access_admin;
use lenso_capability_access_control_directory as access_directory;
use lenso_capability_auth as auth;
use lenso_capability_http_endpoint as http_endpoint_contract;
use lenso_capability_identity_directory as identity;
use lenso_capability_organization_membership_admin as membership;
use lenso_capability_scim_directory as scim;
use lenso_capability_secrets as secrets;
use lenso_kernel::{InvocationContext, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::schema::schema_plan;

pub use operator::{ScimProvisioningOperator, ScimProvisioningOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const SCIM_CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScimProvisioningConfig {
    schema: String,
    database_url_secret: String,
    organization_id: String,
    identity_provider: String,
    directory_callers: Vec<String>,
    repair_callers: Vec<String>,
    http_callers: Vec<String>,
    accepted_actor_kinds: Vec<String>,
    required_organization_claim: String,
    max_page_size: i64,
    max_group_members: usize,
}

impl ScimProvisioningConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| ConfigError::Schema)?;
        if !valid_name(&self.database_url_secret, 256)
            || !valid_name(&self.organization_id, 256)
            || !valid_name(&self.identity_provider, 128)
        {
            return Err(ConfigError::Identity);
        }
        for callers in [
            &self.directory_callers,
            &self.repair_callers,
            &self.http_callers,
        ] {
            if callers.is_empty()
                || callers.iter().any(|value| !valid_name(value, 256))
                || callers.iter().collect::<BTreeSet<_>>().len() != callers.len()
            {
                return Err(ConfigError::Callers);
            }
        }
        if self.accepted_actor_kinds != ["service_account"]
            || self.required_organization_claim != "organization_id"
            || !(1..=200).contains(&self.max_page_size)
            || !(1..=10_000).contains(&self.max_group_members)
        {
            return Err(ConfigError::SecurityBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
enum ConfigError {
    #[error("invalid owned PostgreSQL schema")]
    Schema,
    #[error("invalid SCIM identity or secret configuration")]
    Identity,
    #[error("caller lists must be non-empty, unique, and valid")]
    Callers,
    #[error("invalid SCIM security or resource bound")]
    SecurityBoundary,
}

fn validate_config(config: &ScimProvisioningConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct ScimProvisioningPlugin {
    #[config]
    config: ScimProvisioningConfig,
    secrets: Port<secrets::SecretsClient>,
    auth: Port<auth::AuthClient>,
    identity: Port<identity::DirectoryClient>,
    membership: Port<membership::OrganizationMembershipAdminClient>,
    access_admin: Port<access_admin::AccessControlAdminClient>,
    access_directory: Port<access_directory::AccessControlDirectoryClient>,
    state: Rc<RefCell<Option<PreparedScim>>>,
}

#[derive(Clone)]
struct PreparedScim {
    postgres: OwnedPostgres,
}

impl fmt::Debug for PreparedScim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedScim")
            .field("schema", &self.postgres.schema())
            .finish()
    }
}

impl fmt::Debug for ScimProvisioningPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScimProvisioningPlugin")
            .field("organization_id", &self.config.organization_id)
            .field("prepared", &self.state.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[provides(scim::ScimDirectory)]
impl ScimProvisioningPlugin {
    async fn create_user(
        &self,
        context: InvocationContext,
        request: scim::CreateUserRequest,
    ) -> PluginResult<scim::CreateUserResponse, scim::CreateUserError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::CreateUserError::Unauthorized))?;
        into_plugin(
            self.create_user_value(&context, &caller, request).await,
            map_create_user_error,
        )
    }

    async fn get_user(
        &self,
        context: InvocationContext,
        request: scim::GetUserRequest,
    ) -> PluginResult<scim::GetUserResponse, scim::GetUserError> {
        self.require_directory(&context, &request.organization_id)
            .map_err(|failure| PluginError::domain(map_get_user_error(failure)))?;
        into_plugin(
            self.load_user_value(&request.organization_id, &request.resource_id, false)
                .await,
            map_get_user_error,
        )
    }

    async fn list_users(
        &self,
        context: InvocationContext,
        request: scim::ListUsersRequest,
    ) -> PluginResult<scim::ListUsersResponse, scim::ListUsersError> {
        self.require_directory(&context, &request.organization_id)
            .map_err(|failure| PluginError::domain(map_list_users_error(failure)))?;
        into_plugin(self.list_users_value(request).await, map_list_users_error)
    }

    async fn replace_user(
        &self,
        context: InvocationContext,
        request: scim::ReplaceUserRequest,
    ) -> PluginResult<scim::ReplaceUserResponse, scim::ReplaceUserError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::ReplaceUserError::Unauthorized))?;
        into_plugin(
            self.replace_user_value(&context, &caller, request).await,
            map_replace_user_error,
        )
    }

    async fn patch_user(
        &self,
        context: InvocationContext,
        request: scim::PatchUserRequest,
    ) -> PluginResult<scim::PatchUserResponse, scim::PatchUserError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::PatchUserError::Unauthorized))?;
        into_plugin(
            self.patch_user_value(&context, &caller, request).await,
            map_patch_user_error,
        )
    }

    async fn delete_user(
        &self,
        context: InvocationContext,
        request: scim::DeleteUserRequest,
    ) -> PluginResult<scim::DeleteUserResponse, scim::DeleteUserError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::DeleteUserError::Unauthorized))?;
        into_plugin(
            self.delete_user_value(&context, &caller, request).await,
            map_delete_user_error,
        )
    }

    async fn create_group(
        &self,
        context: InvocationContext,
        request: scim::CreateGroupRequest,
    ) -> PluginResult<scim::CreateGroupResponse, scim::CreateGroupError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::CreateGroupError::Unauthorized))?;
        into_plugin(
            self.create_group_value(&context, &caller, request).await,
            map_create_group_error,
        )
    }

    async fn get_group(
        &self,
        context: InvocationContext,
        request: scim::GetGroupRequest,
    ) -> PluginResult<scim::GetGroupResponse, scim::GetGroupError> {
        self.require_directory(&context, &request.organization_id)
            .map_err(|failure| PluginError::domain(map_get_group_error(failure)))?;
        into_plugin(
            self.load_group_value(&request.organization_id, &request.resource_id, false)
                .await,
            map_get_group_error,
        )
    }

    async fn list_groups(
        &self,
        context: InvocationContext,
        request: scim::ListGroupsRequest,
    ) -> PluginResult<scim::ListGroupsResponse, scim::ListGroupsError> {
        self.require_directory(&context, &request.organization_id)
            .map_err(|failure| PluginError::domain(map_list_groups_error(failure)))?;
        into_plugin(self.list_groups_value(request).await, map_list_groups_error)
    }

    async fn replace_group(
        &self,
        context: InvocationContext,
        request: scim::ReplaceGroupRequest,
    ) -> PluginResult<scim::ReplaceGroupResponse, scim::ReplaceGroupError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::ReplaceGroupError::Unauthorized))?;
        into_plugin(
            self.replace_group_value(&context, &caller, request).await,
            map_replace_group_error,
        )
    }

    async fn patch_group(
        &self,
        context: InvocationContext,
        request: scim::PatchGroupRequest,
    ) -> PluginResult<scim::PatchGroupResponse, scim::PatchGroupError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::PatchGroupError::Unauthorized))?;
        into_plugin(
            self.patch_group_value(&context, &caller, request).await,
            map_patch_group_error,
        )
    }

    async fn delete_group(
        &self,
        context: InvocationContext,
        request: scim::DeleteGroupRequest,
    ) -> PluginResult<scim::DeleteGroupResponse, scim::DeleteGroupError> {
        let caller = self
            .directory_caller(&context)
            .ok_or_else(|| PluginError::domain(scim::DeleteGroupError::Unauthorized))?;
        into_plugin(
            self.delete_group_value(&context, &caller, request).await,
            map_delete_group_error,
        )
    }

    async fn repair_sync(
        &self,
        context: InvocationContext,
        request: scim::RepairSyncRequest,
    ) -> PluginResult<scim::RepairSyncResponse, scim::RepairSyncError> {
        if !caller_allowed(&context, &self.config.repair_callers)
            || request.organization_id != self.config.organization_id
            || !(1..=100).contains(&request.limit)
        {
            return Err(PluginError::domain(scim::RepairSyncError::Unauthorized));
        }
        into_plugin(
            self.repair_sync_value(&context, request.limit).await,
            map_repair_error,
        )
    }
}

type DirectoryResult<T> = Result<Result<T, DirectoryFailure>, RuntimeFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryFailure {
    Unauthorized,
    InvalidRequest,
    NotFound,
    Conflict,
    PreconditionFailed,
    DownstreamRejected,
}

#[derive(Clone, Debug)]
enum CommandClaim {
    New,
    Pending,
    Replay(Value),
    Conflict,
}

#[derive(Clone, Debug)]
struct UserRecord {
    id: String,
    organization_id: String,
    external_id: Option<String>,
    user_name: String,
    display_name: Option<String>,
    emails: Value,
    active: bool,
    subject: String,
    version: i64,
    sync_status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl UserRecord {
    fn from_row(row: &PgRow) -> Result<Self, RuntimeFailure> {
        Ok(Self {
            id: row.try_get("id").map_err(database)?,
            organization_id: row.try_get("organization_id").map_err(database)?,
            external_id: row.try_get("external_id").map_err(database)?,
            user_name: row.try_get("user_name").map_err(database)?,
            display_name: row.try_get("display_name").map_err(database)?,
            emails: row.try_get("emails").map_err(database)?,
            active: row.try_get("active").map_err(database)?,
            subject: row.try_get("subject").map_err(database)?,
            version: row.try_get("version").map_err(database)?,
            sync_status: row.try_get("sync_status").map_err(database)?,
            created_at: row.try_get("created_at").map_err(database)?,
            updated_at: row.try_get("updated_at").map_err(database)?,
        })
    }

    fn value(&self) -> Value {
        json!({
            "id": self.id,
            "organization_id": self.organization_id,
            "external_id": self.external_id,
            "user_name": self.user_name,
            "display_name": self.display_name,
            "emails": self.emails,
            "active": self.active,
            "subject": self.subject,
            "version": self.version.to_string(),
            "created_at": self.created_at.format(&Rfc3339).expect("database timestamp formats"),
            "updated_at": self.updated_at.format(&Rfc3339).expect("database timestamp formats"),
            "sync_status": self.sync_status,
        })
    }
}

#[derive(Clone, Debug)]
struct GroupRecord {
    id: String,
    organization_id: String,
    external_id: Option<String>,
    display_name: String,
    role_id: Option<String>,
    version: i64,
    sync_status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    members: Vec<String>,
}

impl GroupRecord {
    fn from_row(row: &PgRow, members: Vec<String>) -> Result<Self, RuntimeFailure> {
        Ok(Self {
            id: row.try_get("id").map_err(database)?,
            organization_id: row.try_get("organization_id").map_err(database)?,
            external_id: row.try_get("external_id").map_err(database)?,
            display_name: row.try_get("display_name").map_err(database)?,
            role_id: row.try_get("role_id").map_err(database)?,
            version: row.try_get("version").map_err(database)?,
            sync_status: row.try_get("sync_status").map_err(database)?,
            created_at: row.try_get("created_at").map_err(database)?,
            updated_at: row.try_get("updated_at").map_err(database)?,
            members,
        })
    }

    fn value(&self) -> Value {
        json!({
            "id": self.id,
            "organization_id": self.organization_id,
            "external_id": self.external_id,
            "display_name": self.display_name,
            "member_user_ids": self.members,
            "role_id": self.role_id,
            "version": self.version.to_string(),
            "created_at": self.created_at.format(&Rfc3339).expect("database timestamp formats"),
            "updated_at": self.updated_at.format(&Rfc3339).expect("database timestamp formats"),
            "sync_status": self.sync_status,
        })
    }
}

fn into_plugin<T, E>(
    result: DirectoryResult<Value>,
    map_error: fn(DirectoryFailure) -> E,
) -> PluginResult<T, E>
where
    T: DeserializeOwned,
{
    match result {
        Ok(Ok(value)) => {
            serde_json::from_value(value).map_err(|error| PluginError::runtime(protocol(error)))
        }
        Ok(Err(error)) => Err(PluginError::domain(map_error(error))),
        Err(error) => Err(PluginError::runtime(error)),
    }
}

macro_rules! directory_error_mapper {
    ($name:ident, $ty:path) => {
        fn $name(failure: DirectoryFailure) -> $ty {
            match failure {
                DirectoryFailure::Unauthorized => <$ty>::Unauthorized,
                DirectoryFailure::InvalidRequest => <$ty>::InvalidRequest,
                DirectoryFailure::NotFound => <$ty>::NotFound,
                DirectoryFailure::Conflict => <$ty>::Conflict,
                DirectoryFailure::PreconditionFailed => <$ty>::PreconditionFailed,
                DirectoryFailure::DownstreamRejected => <$ty>::DownstreamRejected,
            }
        }
    };
}

directory_error_mapper!(map_create_user_error, scim::CreateUserError);
directory_error_mapper!(map_get_user_error, scim::GetUserError);
directory_error_mapper!(map_list_users_error, scim::ListUsersError);
directory_error_mapper!(map_replace_user_error, scim::ReplaceUserError);
directory_error_mapper!(map_patch_user_error, scim::PatchUserError);
directory_error_mapper!(map_delete_user_error, scim::DeleteUserError);
directory_error_mapper!(map_create_group_error, scim::CreateGroupError);
directory_error_mapper!(map_get_group_error, scim::GetGroupError);
directory_error_mapper!(map_list_groups_error, scim::ListGroupsError);
directory_error_mapper!(map_replace_group_error, scim::ReplaceGroupError);
directory_error_mapper!(map_patch_group_error, scim::PatchGroupError);
directory_error_mapper!(map_delete_group_error, scim::DeleteGroupError);
directory_error_mapper!(map_repair_error, scim::RepairSyncError);

fn failure(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.into(),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn database(error: sqlx::Error) -> RuntimeFailure {
    failure(format!("SCIM PostgreSQL operation failed: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
fn protocol(error: serde_json::Error) -> RuntimeFailure {
    RuntimeFailure::Internal {
        detail: format!("SCIM portable representation failed: {error}"),
    }
}

fn valid_name(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn parse_revision(value: Option<&str>) -> Option<i64> {
    value?.parse().ok().filter(|value| *value > 0)
}

fn caller_allowed(context: &InvocationContext, allowed: &[String]) -> bool {
    context
        .caller_instance()
        .is_some_and(|caller| allowed.iter().any(|entry| entry == caller))
}

fn request_hash(value: &Value) -> Result<Vec<u8>, RuntimeFailure> {
    serde_json::to_vec(value)
        .map(|bytes| Sha256::digest(bytes).to_vec())
        .map_err(protocol)
}

fn stable_resource_id(prefix: &str, caller: &str, key: &str) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(format!("{caller}\0{key}"));
    let suffix = digest[..16]
        .iter()
        .fold(String::with_capacity(32), |mut suffix, byte| {
            write!(suffix, "{byte:02x}").expect("writing to String cannot fail");
            suffix
        });
    format!("{prefix}_{suffix}")
}

fn validate_user_write<T: Serialize>(
    user_name: &str,
    display_name: Option<&str>,
    emails: &[T],
    expected_version: Option<&str>,
    create: bool,
    _maximum: usize,
) -> Result<(), DirectoryFailure> {
    if !valid_name(user_name, 320)
        || display_name.is_some_and(|value| !valid_name(value, 512))
        || emails.len() > 32
        || (create && expected_version.is_some())
        || (!create && parse_revision(expected_version).is_none())
    {
        return Err(DirectoryFailure::InvalidRequest);
    }
    let value = serde_json::to_value(emails).map_err(|_| DirectoryFailure::InvalidRequest)?;
    let Some(items) = value.as_array() else {
        return Err(DirectoryFailure::InvalidRequest);
    };
    if items.iter().any(|item| {
        !item
            .get("value")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_name(value, 320) && value.contains('@'))
    }) || items
        .iter()
        .filter(|item| item.get("primary") == Some(&Value::Bool(true)))
        .count()
        > 1
    {
        return Err(DirectoryFailure::InvalidRequest);
    }
    Ok(())
}

impl ScimProvisioningPlugin {
    fn prepared(&self) -> Result<PreparedScim, RuntimeFailure> {
        self.state
            .borrow()
            .clone()
            .ok_or_else(|| failure("SCIM Provisioning Plugin is not prepared"))
    }

    fn directory_caller(&self, context: &InvocationContext) -> Option<String> {
        context.caller_instance().and_then(|caller| {
            self.config
                .directory_callers
                .iter()
                .any(|allowed| allowed == caller)
                .then(|| caller.to_owned())
        })
    }

    fn require_directory(
        &self,
        context: &InvocationContext,
        organization_id: &str,
    ) -> Result<(), DirectoryFailure> {
        if self.directory_caller(context).is_none() {
            return Err(DirectoryFailure::Unauthorized);
        }
        self.require_organization(organization_id)
    }

    fn require_organization(&self, organization_id: &str) -> Result<(), DirectoryFailure> {
        if organization_id != self.config.organization_id {
            return Err(DirectoryFailure::InvalidRequest);
        }
        Ok(())
    }

    async fn create_user_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::CreateUserRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        if let Err(error) = validate_user_write(
            &request.user_name,
            request.display_name.as_deref(),
            &request.emails,
            request.expected_version.as_deref(),
            true,
            self.config.max_group_members,
        ) {
            return Ok(Err(error));
        }
        if request.expected_version.is_some() {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::CREATE_USER_OPERATION,
                &request.idempotency_key,
                "user",
                request.resource_id.as_deref(),
                &request_json,
            )
            .await?;
        if let CommandClaim::Replay(value) = claim {
            return Ok(Ok(value));
        }
        if matches!(claim, CommandClaim::Conflict) {
            return Ok(Err(DirectoryFailure::Conflict));
        }
        let external_subject = request
            .external_id
            .clone()
            .unwrap_or_else(|| request.user_name.clone());
        let identity = self
            .identity
            .ensure_identity_with_context(
                context.clone(),
                identity::EnsureIdentityRequest {
                    provider: self.config.identity_provider.clone(),
                    external_subject,
                },
            )
            .await;
        let subject = match identity {
            Ok(response) if valid_name(&response.subject, 256) => response.subject,
            Ok(_) | Err(identity::DirectoryEnsureIdentityInvocationError::Domain(_)) => {
                self.fail_command(
                    caller,
                    scim::CREATE_USER_OPERATION,
                    &request.idempotency_key,
                    "identity_rejected",
                )
                .await?;
                return Ok(Err(DirectoryFailure::DownstreamRejected));
            }
            Err(identity::DirectoryEnsureIdentityInvocationError::Runtime(error)) => {
                self.pending_command(
                    caller,
                    scim::CREATE_USER_OPERATION,
                    &request.idempotency_key,
                    "identity_runtime",
                )
                .await?;
                return Err(error);
            }
        };
        let retry = matches!(claim, CommandClaim::Pending);
        let id = request
            .resource_id
            .clone()
            .unwrap_or_else(|| stable_resource_id("usr", caller, &request.idempotency_key));
        let emails = serde_json::to_value(&request.emails).map_err(protocol)?;
        let prepared = self.prepared()?;
        let inserted = sqlx::query(
            "INSERT INTO scim_users(id,organization_id,external_id,user_name,display_name,emails,active,subject,version,sync_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,'pending') ON CONFLICT DO NOTHING",
        )
        .bind(&id)
        .bind(&request.organization_id)
        .bind(&request.external_id)
        .bind(&request.user_name)
        .bind(&request.display_name)
        .bind(&emails)
        .bind(request.active)
        .bind(&subject)
        .execute(prepared.postgres.pool())
        .await
        .map_err(database)?
        .rows_affected();
        if inserted == 0 {
            if retry
                && self
                    .load_user_record(&request.organization_id, &id, true)
                    .await?
                    .is_some()
            {
                let converged = self.sync_user(context, &id).await?;
                let value = match self
                    .load_user_value(&request.organization_id, &id, true)
                    .await?
                {
                    Ok(value) => value,
                    Err(error) => return Ok(Err(error)),
                };
                self.finish_command(
                    caller,
                    scim::CREATE_USER_OPERATION,
                    &request.idempotency_key,
                    &value,
                    converged,
                )
                .await?;
                return Ok(Ok(value));
            }
            return Ok(Err(DirectoryFailure::Conflict));
        }
        sqlx::query("INSERT INTO scim_membership_projection(user_id,subject,desired,applied) VALUES($1,$2,$3,false)")
            .bind(&id)
            .bind(&subject)
            .bind(request.active)
            .execute(prepared.postgres.pool())
            .await
            .map_err(database)?;
        self.attach_command_resource(
            caller,
            scim::CREATE_USER_OPERATION,
            &request.idempotency_key,
            &id,
        )
        .await?;
        let converged = self.sync_user(context, &id).await?;
        let value = match self
            .load_user_value(&request.organization_id, &id, true)
            .await?
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        if converged {
            self.complete_command(
                caller,
                scim::CREATE_USER_OPERATION,
                &request.idempotency_key,
                &value,
            )
            .await?;
        } else {
            self.pending_command(
                caller,
                scim::CREATE_USER_OPERATION,
                &request.idempotency_key,
                "membership_pending",
            )
            .await?;
        }
        Ok(Ok(value))
    }

    async fn replace_user_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::ReplaceUserRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        let Some(resource_id) = request.resource_id.clone() else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        let Some(expected) = parse_revision(request.expected_version.as_deref()) else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        if let Err(error) = validate_user_write(
            &request.user_name,
            request.display_name.as_deref(),
            &request.emails,
            request.expected_version.as_deref(),
            false,
            self.config.max_group_members,
        ) {
            return Ok(Err(error));
        }
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::REPLACE_USER_OPERATION,
                &request.idempotency_key,
                "user",
                Some(&resource_id),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        if matches!(claim, CommandClaim::Pending) {
            match self
                .recover_user_command(
                    context,
                    caller,
                    scim::REPLACE_USER_OPERATION,
                    &request.idempotency_key,
                    &request.organization_id,
                    &resource_id,
                )
                .await?
            {
                Ok(Some(value)) => return Ok(Ok(value)),
                Ok(None) => {}
                Err(error) => return Ok(Err(error)),
            }
        }
        let emails = serde_json::to_value(&request.emails).map_err(protocol)?;
        let prepared = self.prepared()?;
        let row = sqlx::query("UPDATE scim_users SET external_id=$1,user_name=$2,display_name=$3,emails=$4,active=$5,version=version+1,sync_status='pending',updated_at=transaction_timestamp() WHERE organization_id=$6 AND id=$7 AND version=$8 AND deleted_at IS NULL RETURNING subject")
            .bind(&request.external_id)
            .bind(&request.user_name)
            .bind(&request.display_name)
            .bind(&emails)
            .bind(request.active)
            .bind(&request.organization_id)
            .bind(&resource_id)
            .bind(expected)
            .fetch_optional(prepared.postgres.pool())
            .await
            .map_err(database)?;
        let Some(row) = row else {
            return self
                .cas_failure(&request.organization_id, &resource_id)
                .await;
        };
        let subject: String = row.try_get("subject").map_err(database)?;
        upsert_membership_projection(&prepared, &resource_id, &subject, request.active).await?;
        self.attach_command_resource(
            caller,
            scim::REPLACE_USER_OPERATION,
            &request.idempotency_key,
            &resource_id,
        )
        .await?;
        let converged = self.sync_user(context, &resource_id).await?;
        let value = match self
            .load_user_value(&request.organization_id, &resource_id, true)
            .await?
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        self.finish_command(
            caller,
            scim::REPLACE_USER_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }

    async fn patch_user_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::PatchUserRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        let Some(expected) = parse_revision(Some(&request.expected_version)) else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        if request.user_name.is_none()
            && request.external_id.is_none()
            && request.display_name.is_none()
            && request.emails.is_none()
            && request.active.is_none()
            && request.remove_fields.as_ref().is_none_or(Vec::is_empty)
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::PATCH_USER_OPERATION,
                &request.idempotency_key,
                "user",
                Some(&request.resource_id),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        if matches!(claim, CommandClaim::Pending) {
            match self
                .recover_user_command(
                    context,
                    caller,
                    scim::PATCH_USER_OPERATION,
                    &request.idempotency_key,
                    &request.organization_id,
                    &request.resource_id,
                )
                .await?
            {
                Ok(Some(value)) => return Ok(Ok(value)),
                Ok(None) => {}
                Err(error) => return Ok(Err(error)),
            }
        }
        let current = self
            .load_user_record(&request.organization_id, &request.resource_id, false)
            .await?;
        let Some(mut current) = current else {
            return Ok(Err(DirectoryFailure::NotFound));
        };
        if current.version != expected {
            return Ok(Err(DirectoryFailure::PreconditionFailed));
        }
        if let Some(value) = request.user_name {
            current.user_name = value;
        }
        if let Some(value) = request.external_id {
            current.external_id = Some(value);
        }
        if let Some(value) = request.display_name {
            current.display_name = Some(value);
        }
        if let Some(value) = request.emails {
            current.emails = serde_json::to_value(value).map_err(protocol)?;
        }
        if let Some(value) = request.active {
            current.active = value;
        }
        for field in request.remove_fields.unwrap_or_default() {
            match field {
                scim::PatchUserRequestRemoveFieldsItem::DisplayName => current.display_name = None,
                scim::PatchUserRequestRemoveFieldsItem::Emails => current.emails = json!([]),
                scim::PatchUserRequestRemoveFieldsItem::ExternalId => current.external_id = None,
            }
        }
        if !valid_name(&current.user_name, 320) {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let prepared = self.prepared()?;
        let updated = sqlx::query("UPDATE scim_users SET external_id=$1,user_name=$2,display_name=$3,emails=$4,active=$5,version=version+1,sync_status='pending',updated_at=transaction_timestamp() WHERE organization_id=$6 AND id=$7 AND version=$8 AND deleted_at IS NULL")
            .bind(&current.external_id).bind(&current.user_name).bind(&current.display_name)
            .bind(&current.emails).bind(current.active).bind(&request.organization_id)
            .bind(&request.resource_id).bind(expected)
            .execute(prepared.postgres.pool()).await.map_err(database)?.rows_affected();
        if updated == 0 {
            return self
                .cas_failure(&request.organization_id, &request.resource_id)
                .await;
        }
        upsert_membership_projection(
            &prepared,
            &request.resource_id,
            &current.subject,
            current.active,
        )
        .await?;
        self.attach_command_resource(
            caller,
            scim::PATCH_USER_OPERATION,
            &request.idempotency_key,
            &request.resource_id,
        )
        .await?;
        let converged = self.sync_user(context, &request.resource_id).await?;
        let value = match self
            .load_user_value(&request.organization_id, &request.resource_id, true)
            .await?
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        self.finish_command(
            caller,
            scim::PATCH_USER_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }

    async fn delete_user_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::DeleteUserRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        let Some(expected) = parse_revision(Some(&request.expected_version)) else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::DELETE_USER_OPERATION,
                &request.idempotency_key,
                "user",
                Some(&request.resource_id),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        if matches!(claim, CommandClaim::Pending)
            && self
                .committed_resource(
                    caller,
                    scim::DELETE_USER_OPERATION,
                    &request.idempotency_key,
                )
                .await?
                .as_deref()
                == Some(request.resource_id.as_str())
        {
            let converged = self.sync_user(context, &request.resource_id).await?;
            let Some(record) = self
                .load_user_record(&request.organization_id, &request.resource_id, true)
                .await?
            else {
                return Ok(Err(DirectoryFailure::NotFound));
            };
            let prepared = self.prepared()?;
            sqlx::query("DELETE FROM scim_group_members WHERE user_id=$1")
                .bind(&request.resource_id)
                .execute(prepared.postgres.pool())
                .await
                .map_err(database)?;
            let value = json!({"changed":true,"version":record.version.to_string(),"sync_status":if converged {"converged"} else {"pending"}});
            self.finish_command(
                caller,
                scim::DELETE_USER_OPERATION,
                &request.idempotency_key,
                &value,
                converged,
            )
            .await?;
            return Ok(Ok(value));
        }
        let prepared = self.prepared()?;
        let row = sqlx::query("UPDATE scim_users SET active=false,version=version+1,sync_status='pending',deleted_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=$1 AND id=$2 AND version=$3 AND deleted_at IS NULL RETURNING subject,version")
            .bind(&request.organization_id).bind(&request.resource_id).bind(expected)
            .fetch_optional(prepared.postgres.pool()).await.map_err(database)?;
        let Some(row) = row else {
            return self
                .cas_failure(&request.organization_id, &request.resource_id)
                .await;
        };
        let subject: String = row.try_get("subject").map_err(database)?;
        let version: i64 = row.try_get("version").map_err(database)?;
        sqlx::query("UPDATE scim_groups SET version=version+1,sync_status='pending',updated_at=transaction_timestamp() WHERE deleted_at IS NULL AND id IN (SELECT group_id FROM scim_group_members WHERE user_id=$1)")
            .bind(&request.resource_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        upsert_membership_projection(&prepared, &request.resource_id, &subject, false).await?;
        self.attach_command_resource(
            caller,
            scim::DELETE_USER_OPERATION,
            &request.idempotency_key,
            &request.resource_id,
        )
        .await?;
        let converged = self.sync_user(context, &request.resource_id).await?;
        sqlx::query("DELETE FROM scim_group_members WHERE user_id=$1")
            .bind(&request.resource_id)
            .execute(prepared.postgres.pool())
            .await
            .map_err(database)?;
        let value = json!({"changed":true,"version":version.to_string(),"sync_status":if converged {"converged"} else {"pending"}});
        self.finish_command(
            caller,
            scim::DELETE_USER_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }
}

impl ScimProvisioningPlugin {
    async fn load_user_record(
        &self,
        organization_id: &str,
        resource_id: &str,
        include_deleted: bool,
    ) -> Result<Option<UserRecord>, RuntimeFailure> {
        let prepared = self.prepared()?;
        let row = if include_deleted {
            sqlx::query("SELECT * FROM scim_users WHERE organization_id=$1 AND id=$2")
                .bind(organization_id)
                .bind(resource_id)
                .fetch_optional(prepared.postgres.pool())
                .await
        } else {
            sqlx::query("SELECT * FROM scim_users WHERE organization_id=$1 AND id=$2 AND deleted_at IS NULL")
                .bind(organization_id)
                .bind(resource_id)
                .fetch_optional(prepared.postgres.pool())
                .await
        }
        .map_err(database)?;
        row.as_ref().map(UserRecord::from_row).transpose()
    }

    async fn load_user_value(
        &self,
        organization_id: &str,
        resource_id: &str,
        include_deleted: bool,
    ) -> DirectoryResult<Value> {
        Ok(
            match self
                .load_user_record(organization_id, resource_id, include_deleted)
                .await?
            {
                Some(record) => Ok(record.value()),
                None => Err(DirectoryFailure::NotFound),
            },
        )
    }

    async fn list_users_value(&self, request: scim::ListUsersRequest) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        if request.start_index < 1 || request.count < 1 || request.count > self.config.max_page_size
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let filter = match parse_filter(
            request.filter.as_deref(),
            &["userName", "externalId", "displayName"],
        ) {
            Ok(filter) => filter,
            Err(error) => return Ok(Err(error)),
        };
        let prepared = self.prepared()?;
        let offset = request.start_index - 1;
        let (count_sql, page_sql) = match filter.as_ref().map(|filter| filter.attribute.as_str()) {
            None => (
                "SELECT count(*) AS count FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL",
                "SELECT * FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL ORDER BY id OFFSET $2 LIMIT $3",
            ),
            Some("userName") => (
                "SELECT count(*) AS count FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL AND user_name=$2",
                "SELECT * FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL AND user_name=$2 ORDER BY id OFFSET $3 LIMIT $4",
            ),
            Some("externalId") => (
                "SELECT count(*) AS count FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL AND external_id=$2",
                "SELECT * FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL AND external_id=$2 ORDER BY id OFFSET $3 LIMIT $4",
            ),
            Some("displayName") => (
                "SELECT count(*) AS count FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL AND display_name=$2",
                "SELECT * FROM scim_users WHERE organization_id=$1 AND deleted_at IS NULL AND display_name=$2 ORDER BY id OFFSET $3 LIMIT $4",
            ),
            Some(_) => unreachable!("filter parser returns an allowed attribute"),
        };
        let (total, rows) = if let Some(filter) = filter {
            let total: i64 = sqlx::query(count_sql)
                .bind(&request.organization_id)
                .bind(&filter.value)
                .fetch_one(prepared.postgres.pool())
                .await
                .map_err(database)?
                .try_get("count")
                .map_err(database)?;
            let rows = sqlx::query(page_sql)
                .bind(&request.organization_id)
                .bind(filter.value)
                .bind(offset)
                .bind(request.count)
                .fetch_all(prepared.postgres.pool())
                .await
                .map_err(database)?;
            (total, rows)
        } else {
            let total: i64 = sqlx::query(count_sql)
                .bind(&request.organization_id)
                .fetch_one(prepared.postgres.pool())
                .await
                .map_err(database)?
                .try_get("count")
                .map_err(database)?;
            let rows = sqlx::query(page_sql)
                .bind(&request.organization_id)
                .bind(offset)
                .bind(request.count)
                .fetch_all(prepared.postgres.pool())
                .await
                .map_err(database)?;
            (total, rows)
        };
        let resources = rows
            .iter()
            .map(UserRecord::from_row)
            .map(|record| record.map(|record| record.value()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Ok(json!({
            "resources": resources,
            "total_results": total,
            "start_index": request.start_index,
            "items_per_page": resources.len(),
        })))
    }

    async fn cas_failure(
        &self,
        organization_id: &str,
        resource_id: &str,
    ) -> DirectoryResult<Value> {
        let exists = self
            .load_user_record(organization_id, resource_id, false)
            .await?
            .is_some();
        Ok(Err(if exists {
            DirectoryFailure::PreconditionFailed
        } else {
            DirectoryFailure::NotFound
        }))
    }

    async fn claim_command(
        &self,
        caller: &str,
        operation: &str,
        idempotency_key: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        request: &Value,
    ) -> Result<CommandClaim, RuntimeFailure> {
        if !valid_name(idempotency_key, 256) {
            return Ok(CommandClaim::Conflict);
        }
        let prepared = self.prepared()?;
        let hash = request_hash(request)?;
        let inserted = sqlx::query("INSERT INTO scim_sync_receipts(caller_instance,operation,idempotency_key,request_hash,organization_id,resource_type,resource_id,status,step,request_json) VALUES($1,$2,$3,$4,$5,$6,$7,'in_progress','claimed',$8) ON CONFLICT DO NOTHING")
            .bind(caller)
            .bind(operation)
            .bind(idempotency_key)
            .bind(&hash)
            .bind(&self.config.organization_id)
            .bind(resource_type)
            .bind(resource_id)
            .bind(request)
            .execute(prepared.postgres.pool())
            .await
            .map_err(database)?
            .rows_affected();
        if inserted == 1 {
            return Ok(CommandClaim::New);
        }
        let row = sqlx::query("SELECT request_hash,result_json FROM scim_sync_receipts WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3")
            .bind(caller)
            .bind(operation)
            .bind(idempotency_key)
            .fetch_one(prepared.postgres.pool())
            .await
            .map_err(database)?;
        let existing: Vec<u8> = row.try_get("request_hash").map_err(database)?;
        if existing != hash {
            return Ok(CommandClaim::Conflict);
        }
        if let Some(value) = row
            .try_get::<Option<Value>, _>("result_json")
            .map_err(database)?
        {
            return Ok(CommandClaim::Replay(value));
        }
        sqlx::query("UPDATE scim_sync_receipts SET status='in_progress',updated_at=transaction_timestamp() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3")
            .bind(caller).bind(operation).bind(idempotency_key)
            .execute(prepared.postgres.pool()).await.map_err(database)?;
        Ok(CommandClaim::Pending)
    }

    async fn committed_resource(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
    ) -> Result<Option<String>, RuntimeFailure> {
        let prepared = self.prepared()?;
        let row = sqlx::query("SELECT resource_id,step FROM scim_sync_receipts WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3")
            .bind(caller).bind(operation).bind(key)
            .fetch_optional(prepared.postgres.pool()).await.map_err(database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let step: String = row.try_get("step").map_err(database)?;
        if step != "local_committed" {
            return Ok(None);
        }
        row.try_get("resource_id").map_err(database)
    }

    async fn recover_user_command(
        &self,
        context: &InvocationContext,
        caller: &str,
        operation: &str,
        key: &str,
        organization_id: &str,
        resource_id: &str,
    ) -> DirectoryResult<Option<Value>> {
        if self
            .committed_resource(caller, operation, key)
            .await?
            .as_deref()
            != Some(resource_id)
        {
            return Ok(Ok(None));
        }
        let converged = self.sync_user(context, resource_id).await?;
        let Some(record) = self
            .load_user_record(organization_id, resource_id, true)
            .await?
        else {
            return Ok(Err(DirectoryFailure::NotFound));
        };
        let value = record.value();
        self.finish_command(caller, operation, key, &value, converged)
            .await?;
        Ok(Ok(Some(value)))
    }

    async fn recover_group_command(
        &self,
        context: &InvocationContext,
        caller: &str,
        operation: &str,
        key: &str,
        organization_id: &str,
        resource_id: &str,
    ) -> DirectoryResult<Option<Value>> {
        if self
            .committed_resource(caller, operation, key)
            .await?
            .as_deref()
            != Some(resource_id)
        {
            return Ok(Ok(None));
        }
        let converged = self.sync_group(context, resource_id).await?;
        let Some(record) = self
            .load_group_record(organization_id, resource_id, true)
            .await?
        else {
            return Ok(Err(DirectoryFailure::NotFound));
        };
        let value = record.value();
        self.finish_command(caller, operation, key, &value, converged)
            .await?;
        Ok(Ok(Some(value)))
    }

    async fn attach_command_resource(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        resource_id: &str,
    ) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared()?;
        sqlx::query("UPDATE scim_sync_receipts SET resource_id=$1,step='local_committed',updated_at=transaction_timestamp() WHERE caller_instance=$2 AND operation=$3 AND idempotency_key=$4")
            .bind(resource_id).bind(caller).bind(operation).bind(key)
            .execute(prepared.postgres.pool()).await.map_err(database)?;
        Ok(())
    }

    async fn complete_command(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        value: &Value,
    ) -> Result<(), RuntimeFailure> {
        self.store_command_result(caller, operation, key, value, "completed", "converged")
            .await
    }

    async fn finish_command(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        value: &Value,
        converged: bool,
    ) -> Result<(), RuntimeFailure> {
        self.store_command_result(
            caller,
            operation,
            key,
            value,
            if converged { "completed" } else { "pending" },
            if converged {
                "converged"
            } else {
                "repair_required"
            },
        )
        .await
    }

    async fn store_command_result(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        value: &Value,
        status: &str,
        step: &str,
    ) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared()?;
        sqlx::query("UPDATE scim_sync_receipts SET status=$1,step=$2,result_json=$3,error_code=NULL,updated_at=transaction_timestamp() WHERE caller_instance=$4 AND operation=$5 AND idempotency_key=$6")
            .bind(status).bind(step).bind(value).bind(caller).bind(operation).bind(key)
            .execute(prepared.postgres.pool()).await.map_err(database)?;
        Ok(())
    }

    async fn pending_command(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        step: &str,
    ) -> Result<(), RuntimeFailure> {
        self.mark_command(caller, operation, key, "pending", step)
            .await
    }

    async fn fail_command(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        code: &str,
    ) -> Result<(), RuntimeFailure> {
        self.mark_command(caller, operation, key, "failed", code)
            .await
    }

    async fn mark_command(
        &self,
        caller: &str,
        operation: &str,
        key: &str,
        status: &str,
        code: &str,
    ) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared()?;
        sqlx::query("UPDATE scim_sync_receipts SET status=$1,step=$2,error_code=$2,updated_at=transaction_timestamp() WHERE caller_instance=$3 AND operation=$4 AND idempotency_key=$5")
            .bind(status).bind(code).bind(caller).bind(operation).bind(key)
            .execute(prepared.postgres.pool()).await.map_err(database)?;
        Ok(())
    }

    async fn sync_user(
        &self,
        context: &InvocationContext,
        user_id: &str,
    ) -> Result<bool, RuntimeFailure> {
        let prepared = self.prepared()?;
        let row = sqlx::query(
            "SELECT subject,desired,applied FROM scim_membership_projection WHERE user_id=$1",
        )
        .bind(user_id)
        .fetch_optional(prepared.postgres.pool())
        .await
        .map_err(database)?;
        let Some(row) = row else {
            return Ok(true);
        };
        let subject: String = row.try_get("subject").map_err(database)?;
        let desired: bool = row.try_get("desired").map_err(database)?;
        let applied: bool = row.try_get("applied").map_err(database)?;
        let membership_converged = if desired == applied {
            true
        } else {
            let key = format!("scim:{user_id}:membership:{desired}");
            if desired {
                match self
                    .membership
                    .add_member_with_context(
                        context.clone(),
                        membership::AddMemberRequest {
                            idempotency_key: key,
                            organization_id: self.config.organization_id.clone(),
                            subject: subject.clone(),
                        },
                    )
                    .await
                {
                    Ok(_) => true,
                    Err(
                        membership::OrganizationMembershipAdminAddMemberInvocationError::Domain(_),
                    ) => false,
                    Err(
                        membership::OrganizationMembershipAdminAddMemberInvocationError::Runtime(
                            error,
                        ),
                    ) => return Err(error),
                }
            } else {
                match self
                    .membership
                    .remove_member_with_context(
                        context.clone(),
                        membership::RemoveMemberRequest {
                            idempotency_key: key,
                            organization_id: self.config.organization_id.clone(),
                            subject: subject.clone(),
                        },
                    )
                    .await
                {
                    Ok(_)
                    | Err(
                        membership::OrganizationMembershipAdminRemoveMemberInvocationError::Domain(
                            membership::RemoveMemberError::MembershipNotFound,
                        ),
                    ) => true,
                    Err(
                        membership::OrganizationMembershipAdminRemoveMemberInvocationError::Domain(
                            _,
                        ),
                    ) => false,
                    Err(
                        membership::OrganizationMembershipAdminRemoveMemberInvocationError::Runtime(
                            error,
                        ),
                    ) => return Err(error),
                }
            }
        };
        if membership_converged && desired != applied {
            sqlx::query("UPDATE scim_membership_projection SET applied=desired,updated_at=transaction_timestamp() WHERE user_id=$1")
                .bind(user_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        }
        let group_rows = sqlx::query(
            "SELECT group_id FROM scim_group_members WHERE user_id=$1 ORDER BY group_id",
        )
        .bind(user_id)
        .fetch_all(prepared.postgres.pool())
        .await
        .map_err(database)?;
        let mut roles_converged = true;
        for row in group_rows {
            let group_id: String = row.try_get("group_id").map_err(database)?;
            self.rebuild_role_projection(&group_id).await?;
            roles_converged &= self.sync_group(context, &group_id).await?;
        }
        let converged = membership_converged && roles_converged;
        if converged {
            sqlx::query("UPDATE scim_users SET sync_status='converged',updated_at=transaction_timestamp() WHERE id=$1")
                .bind(user_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        }
        Ok(converged)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedFilter {
    attribute: String,
    value: String,
}

fn parse_filter(
    filter: Option<&str>,
    allowed: &[&str],
) -> Result<Option<ParsedFilter>, DirectoryFailure> {
    let Some(filter) = filter else {
        return Ok(None);
    };
    let Some((attribute, quoted)) = filter.split_once(" eq ") else {
        return Err(DirectoryFailure::InvalidRequest);
    };
    let value = quoted
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(DirectoryFailure::InvalidRequest)?;
    if !allowed.contains(&attribute) || !valid_name(value, 512) || value.contains('"') {
        return Err(DirectoryFailure::InvalidRequest);
    }
    Ok(Some(ParsedFilter {
        attribute: attribute.to_owned(),
        value: value.to_owned(),
    }))
}

async fn upsert_membership_projection(
    prepared: &PreparedScim,
    user_id: &str,
    subject: &str,
    desired: bool,
) -> Result<(), RuntimeFailure> {
    sqlx::query("INSERT INTO scim_membership_projection(user_id,subject,desired,applied) VALUES($1,$2,$3,false) ON CONFLICT(user_id) DO UPDATE SET subject=excluded.subject,desired=excluded.desired,updated_at=transaction_timestamp()")
        .bind(user_id).bind(subject).bind(desired)
        .execute(prepared.postgres.pool()).await.map_err(database)?;
    Ok(())
}

impl ScimProvisioningPlugin {
    async fn create_group_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::CreateGroupRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        if request.expected_version.is_some()
            || !valid_name(&request.display_name, 512)
            || request.member_user_ids.len() > self.config.max_group_members
            || !unique_valid_ids(&request.member_user_ids)
            || request
                .role_id
                .as_deref()
                .is_some_and(|value| !valid_name(value, 256))
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::CREATE_GROUP_OPERATION,
                &request.idempotency_key,
                "group",
                request.resource_id.as_deref(),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        let retry = matches!(claim, CommandClaim::Pending);
        let id = request
            .resource_id
            .clone()
            .unwrap_or_else(|| stable_resource_id("grp", caller, &request.idempotency_key));
        let prepared = self.prepared()?;
        let mut transaction = prepared.postgres.pool().begin().await.map_err(database)?;
        let inserted = sqlx::query("INSERT INTO scim_groups(id,organization_id,external_id,display_name,role_id,version,sync_status) VALUES($1,$2,$3,$4,$5,1,'pending') ON CONFLICT DO NOTHING")
            .bind(&id).bind(&request.organization_id).bind(&request.external_id)
            .bind(&request.display_name).bind(&request.role_id)
            .execute(&mut *transaction).await.map_err(database)?.rows_affected();
        if inserted == 0 {
            transaction.rollback().await.map_err(database)?;
            if retry
                && self
                    .load_group_record(&request.organization_id, &id, true)
                    .await?
                    .is_some()
            {
                self.rebuild_role_projection(&id).await?;
                let converged = self.sync_group(context, &id).await?;
                let value = match self
                    .load_group_value(&request.organization_id, &id, true)
                    .await?
                {
                    Ok(value) => value,
                    Err(error) => return Ok(Err(error)),
                };
                self.finish_command(
                    caller,
                    scim::CREATE_GROUP_OPERATION,
                    &request.idempotency_key,
                    &value,
                    converged,
                )
                .await?;
                return Ok(Ok(value));
            }
            return Ok(Err(DirectoryFailure::Conflict));
        }
        if !members_exist(
            &mut transaction,
            &request.organization_id,
            &request.member_user_ids,
        )
        .await?
        {
            transaction.rollback().await.map_err(database)?;
            return Ok(Err(DirectoryFailure::NotFound));
        }
        for user_id in &request.member_user_ids {
            sqlx::query("INSERT INTO scim_group_members(group_id,user_id) VALUES($1,$2)")
                .bind(&id)
                .bind(user_id)
                .execute(&mut *transaction)
                .await
                .map_err(database)?;
        }
        transaction.commit().await.map_err(database)?;
        self.rebuild_role_projection(&id).await?;
        self.attach_command_resource(
            caller,
            scim::CREATE_GROUP_OPERATION,
            &request.idempotency_key,
            &id,
        )
        .await?;
        let converged = self.sync_group(context, &id).await?;
        let value = match self
            .load_group_value(&request.organization_id, &id, true)
            .await?
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        self.finish_command(
            caller,
            scim::CREATE_GROUP_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }

    async fn replace_group_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::ReplaceGroupRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        let (Some(resource_id), Some(expected)) = (
            request.resource_id.clone(),
            parse_revision(request.expected_version.as_deref()),
        ) else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        if !valid_name(&request.display_name, 512)
            || request.member_user_ids.len() > self.config.max_group_members
            || !unique_valid_ids(&request.member_user_ids)
            || request
                .role_id
                .as_deref()
                .is_some_and(|value| !valid_name(value, 256))
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::REPLACE_GROUP_OPERATION,
                &request.idempotency_key,
                "group",
                Some(&resource_id),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        if matches!(claim, CommandClaim::Pending) {
            match self
                .recover_group_command(
                    context,
                    caller,
                    scim::REPLACE_GROUP_OPERATION,
                    &request.idempotency_key,
                    &request.organization_id,
                    &resource_id,
                )
                .await?
            {
                Ok(Some(value)) => return Ok(Ok(value)),
                Ok(None) => {}
                Err(error) => return Ok(Err(error)),
            }
        }
        let prepared = self.prepared()?;
        let mut transaction = prepared.postgres.pool().begin().await.map_err(database)?;
        if !members_exist(
            &mut transaction,
            &request.organization_id,
            &request.member_user_ids,
        )
        .await?
        {
            transaction.rollback().await.map_err(database)?;
            return Ok(Err(DirectoryFailure::NotFound));
        }
        let updated = sqlx::query("UPDATE scim_groups SET external_id=$1,display_name=$2,role_id=$3,version=version+1,sync_status='pending',updated_at=transaction_timestamp() WHERE organization_id=$4 AND id=$5 AND version=$6 AND deleted_at IS NULL")
            .bind(&request.external_id).bind(&request.display_name).bind(&request.role_id)
            .bind(&request.organization_id).bind(&resource_id).bind(expected)
            .execute(&mut *transaction).await.map_err(database)?.rows_affected();
        if updated == 0 {
            transaction.rollback().await.map_err(database)?;
            return self
                .cas_group_failure(&request.organization_id, &resource_id)
                .await;
        }
        replace_members(&mut transaction, &resource_id, &request.member_user_ids).await?;
        transaction.commit().await.map_err(database)?;
        self.rebuild_role_projection(&resource_id).await?;
        self.attach_command_resource(
            caller,
            scim::REPLACE_GROUP_OPERATION,
            &request.idempotency_key,
            &resource_id,
        )
        .await?;
        let converged = self.sync_group(context, &resource_id).await?;
        let value = match self
            .load_group_value(&request.organization_id, &resource_id, true)
            .await?
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        self.finish_command(
            caller,
            scim::REPLACE_GROUP_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }

    async fn patch_group_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::PatchGroupRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        let Some(expected) = parse_revision(Some(&request.expected_version)) else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        if request.external_id.is_none()
            && request.display_name.is_none()
            && request.role_id.is_none()
            && request.remove_external_id != Some(true)
            && request.remove_role != Some(true)
            && request.members_add.as_ref().is_none_or(Vec::is_empty)
            && request.members_remove.as_ref().is_none_or(Vec::is_empty)
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::PATCH_GROUP_OPERATION,
                &request.idempotency_key,
                "group",
                Some(&request.resource_id),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        if matches!(claim, CommandClaim::Pending) {
            match self
                .recover_group_command(
                    context,
                    caller,
                    scim::PATCH_GROUP_OPERATION,
                    &request.idempotency_key,
                    &request.organization_id,
                    &request.resource_id,
                )
                .await?
            {
                Ok(Some(value)) => return Ok(Ok(value)),
                Ok(None) => {}
                Err(error) => return Ok(Err(error)),
            }
        }
        let Some(current) = self
            .load_group_record(&request.organization_id, &request.resource_id, false)
            .await?
        else {
            return Ok(Err(DirectoryFailure::NotFound));
        };
        if current.version != expected {
            return Ok(Err(DirectoryFailure::PreconditionFailed));
        }
        let mut members = current.members.into_iter().collect::<BTreeSet<_>>();
        for member in request.members_add.clone().unwrap_or_default() {
            members.insert(member);
        }
        for member in request.members_remove.clone().unwrap_or_default() {
            members.remove(&member);
        }
        if members.len() > self.config.max_group_members
            || members.iter().any(|value| !valid_name(value, 256))
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let members = members.into_iter().collect::<Vec<_>>();
        let display_name = request.display_name.clone().unwrap_or(current.display_name);
        let external_id = if request.remove_external_id == Some(true) {
            None
        } else {
            request.external_id.clone().or(current.external_id)
        };
        let role_id = if request.remove_role == Some(true) {
            None
        } else {
            request.role_id.clone().or(current.role_id)
        };
        if !valid_name(&display_name, 512)
            || role_id
                .as_deref()
                .is_some_and(|value| !valid_name(value, 256))
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let prepared = self.prepared()?;
        let mut transaction = prepared.postgres.pool().begin().await.map_err(database)?;
        if !members_exist(&mut transaction, &request.organization_id, &members).await? {
            transaction.rollback().await.map_err(database)?;
            return Ok(Err(DirectoryFailure::NotFound));
        }
        let updated = sqlx::query("UPDATE scim_groups SET external_id=$1,display_name=$2,role_id=$3,version=version+1,sync_status='pending',updated_at=transaction_timestamp() WHERE organization_id=$4 AND id=$5 AND version=$6 AND deleted_at IS NULL")
            .bind(&external_id).bind(&display_name).bind(&role_id).bind(&request.organization_id)
            .bind(&request.resource_id).bind(expected).execute(&mut *transaction).await.map_err(database)?.rows_affected();
        if updated == 0 {
            transaction.rollback().await.map_err(database)?;
            return self
                .cas_group_failure(&request.organization_id, &request.resource_id)
                .await;
        }
        replace_members(&mut transaction, &request.resource_id, &members).await?;
        transaction.commit().await.map_err(database)?;
        self.rebuild_role_projection(&request.resource_id).await?;
        self.attach_command_resource(
            caller,
            scim::PATCH_GROUP_OPERATION,
            &request.idempotency_key,
            &request.resource_id,
        )
        .await?;
        let converged = self.sync_group(context, &request.resource_id).await?;
        let value = match self
            .load_group_value(&request.organization_id, &request.resource_id, true)
            .await?
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(error)),
        };
        self.finish_command(
            caller,
            scim::PATCH_GROUP_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }

    async fn delete_group_value(
        &self,
        context: &InvocationContext,
        caller: &str,
        request: scim::DeleteGroupRequest,
    ) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        let Some(expected) = parse_revision(Some(&request.expected_version)) else {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        };
        let request_json = serde_json::to_value(&request).map_err(protocol)?;
        let claim = self
            .claim_command(
                caller,
                scim::DELETE_GROUP_OPERATION,
                &request.idempotency_key,
                "group",
                Some(&request.resource_id),
                &request_json,
            )
            .await?;
        match &claim {
            CommandClaim::Replay(value) => return Ok(Ok(value.clone())),
            CommandClaim::Conflict => return Ok(Err(DirectoryFailure::Conflict)),
            CommandClaim::New | CommandClaim::Pending => {}
        }
        if matches!(claim, CommandClaim::Pending)
            && self
                .committed_resource(
                    caller,
                    scim::DELETE_GROUP_OPERATION,
                    &request.idempotency_key,
                )
                .await?
                .as_deref()
                == Some(request.resource_id.as_str())
        {
            let converged = self.sync_group(context, &request.resource_id).await?;
            let Some(record) = self
                .load_group_record(&request.organization_id, &request.resource_id, true)
                .await?
            else {
                return Ok(Err(DirectoryFailure::NotFound));
            };
            let value = json!({"changed":true,"version":record.version.to_string(),"sync_status":if converged {"converged"} else {"pending"}});
            self.finish_command(
                caller,
                scim::DELETE_GROUP_OPERATION,
                &request.idempotency_key,
                &value,
                converged,
            )
            .await?;
            return Ok(Ok(value));
        }
        let prepared = self.prepared()?;
        let row = sqlx::query("UPDATE scim_groups SET version=version+1,sync_status='pending',deleted_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE organization_id=$1 AND id=$2 AND version=$3 AND deleted_at IS NULL RETURNING version")
            .bind(&request.organization_id).bind(&request.resource_id).bind(expected)
            .fetch_optional(prepared.postgres.pool()).await.map_err(database)?;
        let Some(row) = row else {
            return self
                .cas_group_failure(&request.organization_id, &request.resource_id)
                .await;
        };
        let version: i64 = row.try_get("version").map_err(database)?;
        sqlx::query("UPDATE scim_role_projection SET desired=false,updated_at=transaction_timestamp() WHERE group_id=$1")
            .bind(&request.resource_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        self.attach_command_resource(
            caller,
            scim::DELETE_GROUP_OPERATION,
            &request.idempotency_key,
            &request.resource_id,
        )
        .await?;
        let converged = self.sync_group(context, &request.resource_id).await?;
        let value = json!({"changed":true,"version":version.to_string(),"sync_status":if converged {"converged"} else {"pending"}});
        self.finish_command(
            caller,
            scim::DELETE_GROUP_OPERATION,
            &request.idempotency_key,
            &value,
            converged,
        )
        .await?;
        Ok(Ok(value))
    }

    async fn load_group_record(
        &self,
        organization_id: &str,
        resource_id: &str,
        include_deleted: bool,
    ) -> Result<Option<GroupRecord>, RuntimeFailure> {
        let prepared = self.prepared()?;
        let row = if include_deleted {
            sqlx::query("SELECT * FROM scim_groups WHERE organization_id=$1 AND id=$2")
        } else {
            sqlx::query("SELECT * FROM scim_groups WHERE organization_id=$1 AND id=$2 AND deleted_at IS NULL")
        }.bind(organization_id).bind(resource_id).fetch_optional(prepared.postgres.pool()).await.map_err(database)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let members = sqlx::query(
            "SELECT user_id FROM scim_group_members WHERE group_id=$1 ORDER BY user_id",
        )
        .bind(resource_id)
        .fetch_all(prepared.postgres.pool())
        .await
        .map_err(database)?
        .iter()
        .map(|row| row.try_get("user_id").map_err(database))
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(GroupRecord::from_row(&row, members)?))
    }

    async fn load_group_value(
        &self,
        organization_id: &str,
        resource_id: &str,
        include_deleted: bool,
    ) -> DirectoryResult<Value> {
        Ok(
            match self
                .load_group_record(organization_id, resource_id, include_deleted)
                .await?
            {
                Some(record) => Ok(record.value()),
                None => Err(DirectoryFailure::NotFound),
            },
        )
    }

    async fn list_groups_value(&self, request: scim::ListGroupsRequest) -> DirectoryResult<Value> {
        if let Err(error) = self.require_organization(&request.organization_id) {
            return Ok(Err(error));
        }
        if request.start_index < 1 || request.count < 1 || request.count > self.config.max_page_size
        {
            return Ok(Err(DirectoryFailure::InvalidRequest));
        }
        let filter = match parse_filter(request.filter.as_deref(), &["displayName", "externalId"]) {
            Ok(filter) => filter,
            Err(error) => return Ok(Err(error)),
        };
        let prepared = self.prepared()?;
        let offset = request.start_index - 1;
        let (count_sql, page_sql) = match filter.as_ref().map(|filter| filter.attribute.as_str()) {
            None => (
                "SELECT count(*) AS count FROM scim_groups WHERE organization_id=$1 AND deleted_at IS NULL",
                "SELECT id FROM scim_groups WHERE organization_id=$1 AND deleted_at IS NULL ORDER BY id OFFSET $2 LIMIT $3",
            ),
            Some("displayName") => (
                "SELECT count(*) AS count FROM scim_groups WHERE organization_id=$1 AND deleted_at IS NULL AND display_name=$2",
                "SELECT id FROM scim_groups WHERE organization_id=$1 AND deleted_at IS NULL AND display_name=$2 ORDER BY id OFFSET $3 LIMIT $4",
            ),
            Some("externalId") => (
                "SELECT count(*) AS count FROM scim_groups WHERE organization_id=$1 AND deleted_at IS NULL AND external_id=$2",
                "SELECT id FROM scim_groups WHERE organization_id=$1 AND deleted_at IS NULL AND external_id=$2 ORDER BY id OFFSET $3 LIMIT $4",
            ),
            Some(_) => unreachable!(),
        };
        let (total, rows) = if let Some(filter) = filter {
            let total: i64 = sqlx::query(count_sql)
                .bind(&request.organization_id)
                .bind(&filter.value)
                .fetch_one(prepared.postgres.pool())
                .await
                .map_err(database)?
                .try_get("count")
                .map_err(database)?;
            let rows = sqlx::query(page_sql)
                .bind(&request.organization_id)
                .bind(filter.value)
                .bind(offset)
                .bind(request.count)
                .fetch_all(prepared.postgres.pool())
                .await
                .map_err(database)?;
            (total, rows)
        } else {
            let total: i64 = sqlx::query(count_sql)
                .bind(&request.organization_id)
                .fetch_one(prepared.postgres.pool())
                .await
                .map_err(database)?
                .try_get("count")
                .map_err(database)?;
            let rows = sqlx::query(page_sql)
                .bind(&request.organization_id)
                .bind(offset)
                .bind(request.count)
                .fetch_all(prepared.postgres.pool())
                .await
                .map_err(database)?;
            (total, rows)
        };
        let mut resources = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("id").map_err(database)?;
            resources.push(
                self.load_group_record(&request.organization_id, &id, false)
                    .await?
                    .expect("selected group exists")
                    .value(),
            );
        }
        Ok(Ok(
            json!({"items_per_page":resources.len(),"resources":resources,"start_index":request.start_index,"total_results":total}),
        ))
    }

    async fn cas_group_failure(
        &self,
        organization_id: &str,
        resource_id: &str,
    ) -> DirectoryResult<Value> {
        Ok(Err(
            if self
                .load_group_record(organization_id, resource_id, false)
                .await?
                .is_some()
            {
                DirectoryFailure::PreconditionFailed
            } else {
                DirectoryFailure::NotFound
            },
        ))
    }

    async fn rebuild_role_projection(&self, group_id: &str) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared()?;
        sqlx::query("UPDATE scim_role_projection SET desired=false,updated_at=transaction_timestamp() WHERE group_id=$1")
            .bind(group_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        sqlx::query("INSERT INTO scim_role_projection(group_id,user_id,subject,role_id,desired,applied) SELECT g.id,m.user_id,u.subject,g.role_id,true,false FROM scim_groups g JOIN scim_group_members m ON m.group_id=g.id JOIN scim_users u ON u.id=m.user_id WHERE g.id=$1 AND g.deleted_at IS NULL AND g.role_id IS NOT NULL AND u.deleted_at IS NULL AND u.active=true ON CONFLICT(group_id,user_id,role_id) DO UPDATE SET subject=excluded.subject,desired=true,updated_at=transaction_timestamp()")
            .bind(group_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        Ok(())
    }

    async fn sync_group(
        &self,
        context: &InvocationContext,
        group_id: &str,
    ) -> Result<bool, RuntimeFailure> {
        let prepared = self.prepared()?;
        let rows = sqlx::query("SELECT user_id,subject,role_id,desired FROM scim_role_projection WHERE group_id=$1 AND desired<>applied ORDER BY user_id,role_id")
            .bind(group_id).fetch_all(prepared.postgres.pool()).await.map_err(database)?;
        let mut all_converged = true;
        for row in rows {
            let user_id: String = row.try_get("user_id").map_err(database)?;
            let subject: String = row.try_get("subject").map_err(database)?;
            let role_id: String = row.try_get("role_id").map_err(database)?;
            let desired: bool = row.try_get("desired").map_err(database)?;
            let scope = access_admin::AssignRoleRequestScope {
                kind: "organization".to_owned(),
                id: self.config.organization_id.clone(),
            };
            let accepted = if desired {
                match self
                    .access_admin
                    .assign_role_with_context(
                        context.clone(),
                        access_admin::AssignRoleRequest {
                            role_id: role_id.clone(),
                            scope,
                            subject: subject.clone(),
                        },
                    )
                    .await
                {
                    Ok(_) => true,
                    Err(access_admin::AccessControlAdminAssignRoleInvocationError::Domain(_)) => {
                        false
                    }
                    Err(access_admin::AccessControlAdminAssignRoleInvocationError::Runtime(
                        error,
                    )) => return Err(error),
                }
            } else {
                match self
                    .access_admin
                    .revoke_role_with_context(
                        context.clone(),
                        access_admin::RevokeRoleRequest {
                            role_id: role_id.clone(),
                            scope: access_admin::RevokeRoleRequestScope {
                                kind: "organization".to_owned(),
                                id: self.config.organization_id.clone(),
                            },
                            subject: subject.clone(),
                        },
                    )
                    .await
                {
                    Ok(_)
                    | Err(access_admin::AccessControlAdminRevokeRoleInvocationError::Domain(
                        access_admin::RevokeRoleError::RoleNotFound,
                    )) => true,
                    Err(access_admin::AccessControlAdminRevokeRoleInvocationError::Domain(_)) => {
                        false
                    }
                    Err(access_admin::AccessControlAdminRevokeRoleInvocationError::Runtime(
                        error,
                    )) => return Err(error),
                }
            };
            let verified =
                accepted && self.role_present(context, &subject, &role_id).await? == desired;
            if verified {
                sqlx::query("UPDATE scim_role_projection SET applied=desired,updated_at=transaction_timestamp() WHERE group_id=$1 AND user_id=$2 AND role_id=$3")
                    .bind(group_id).bind(&user_id).bind(&role_id).execute(prepared.postgres.pool()).await.map_err(database)?;
            } else {
                all_converged = false;
            }
        }
        let pending: i64 = sqlx::query("SELECT count(*) AS count FROM scim_role_projection WHERE group_id=$1 AND desired<>applied")
            .bind(group_id).fetch_one(prepared.postgres.pool()).await.map_err(database)?.try_get("count").map_err(database)?;
        if all_converged && pending == 0 {
            sqlx::query("UPDATE scim_groups SET sync_status='converged',updated_at=transaction_timestamp() WHERE id=$1")
                .bind(group_id).execute(prepared.postgres.pool()).await.map_err(database)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn role_present(
        &self,
        context: &InvocationContext,
        subject: &str,
        role_id: &str,
    ) -> Result<bool, RuntimeFailure> {
        let mut cursor = None;
        for _ in 0..20 {
            let response = match self.access_directory.list_subject_roles_with_context(context.clone(), access_directory::ListSubjectRolesRequest {
                cursor,
                limit: 100,
                scope: access_directory::Scope { kind: "organization".to_owned(), id: self.config.organization_id.clone() },
                subject: subject.to_owned(),
            }).await {
                Ok(response) => response,
                Err(access_directory::AccessControlDirectoryListSubjectRolesInvocationError::Domain(_)) => return Ok(false),
                Err(access_directory::AccessControlDirectoryListSubjectRolesInvocationError::Runtime(error)) => return Err(error),
            };
            if response.roles.iter().any(|role| role.role_id == role_id) {
                return Ok(true);
            }
            let Some(next) = response.next_cursor else {
                return Ok(false);
            };
            cursor = Some(next);
        }
        Err(failure(
            "RBAC role verification exceeded the bounded directory page limit",
        ))
    }
}

fn unique_valid_ids(values: &[String]) -> bool {
    values.iter().all(|value| valid_name(value, 256))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

async fn members_exist(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: &str,
    members: &[String],
) -> Result<bool, RuntimeFailure> {
    for member in members {
        let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM scim_users WHERE organization_id=$1 AND id=$2 AND deleted_at IS NULL) AS exists")
            .bind(organization_id).bind(member).fetch_one(&mut **transaction).await.map_err(database)?.try_get("exists").map_err(database)?;
        if !exists {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn replace_members(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &str,
    members: &[String],
) -> Result<(), RuntimeFailure> {
    sqlx::query("DELETE FROM scim_group_members WHERE group_id=$1")
        .bind(group_id)
        .execute(&mut **transaction)
        .await
        .map_err(database)?;
    for member in members {
        sqlx::query("INSERT INTO scim_group_members(group_id,user_id) VALUES($1,$2)")
            .bind(group_id)
            .bind(member)
            .execute(&mut **transaction)
            .await
            .map_err(database)?;
    }
    Ok(())
}

impl ScimProvisioningPlugin {
    async fn repair_sync_value(
        &self,
        context: &InvocationContext,
        limit: i64,
    ) -> DirectoryResult<Value> {
        let prepared = self.prepared()?;
        let user_rows = sqlx::query("SELECT user_id FROM scim_membership_projection WHERE desired<>applied ORDER BY updated_at,user_id LIMIT $1")
            .bind(limit).fetch_all(prepared.postgres.pool()).await.map_err(database)?;
        let mut inspected = 0_i64;
        let mut converged = 0_i64;
        let mut pending = 0_i64;
        for row in user_rows {
            let user_id: String = row.try_get("user_id").map_err(database)?;
            inspected += 1;
            if self.sync_user(context, &user_id).await? {
                converged += 1;
            } else {
                pending += 1;
            }
        }
        let remaining = limit - inspected;
        if remaining > 0 {
            let group_rows = sqlx::query("SELECT DISTINCT group_id FROM scim_role_projection WHERE desired<>applied ORDER BY group_id LIMIT $1")
                .bind(remaining).fetch_all(prepared.postgres.pool()).await.map_err(database)?;
            for row in group_rows {
                let group_id: String = row.try_get("group_id").map_err(database)?;
                inspected += 1;
                if self.sync_group(context, &group_id).await? {
                    converged += 1;
                } else {
                    pending += 1;
                }
            }
        }
        sqlx::query("UPDATE scim_sync_receipts r SET status='completed',step='repaired',updated_at=transaction_timestamp() WHERE r.organization_id=$1 AND r.status='pending' AND r.result_json IS NOT NULL AND NOT EXISTS (SELECT 1 FROM scim_membership_projection m WHERE m.user_id=r.resource_id AND m.desired<>m.applied) AND NOT EXISTS (SELECT 1 FROM scim_role_projection p WHERE p.group_id=r.resource_id AND p.desired<>p.applied)")
            .bind(&self.config.organization_id).execute(prepared.postgres.pool()).await.map_err(database)?;
        Ok(Ok(
            json!({"inspected":inspected,"converged":converged,"pending":pending,"failed":0}),
        ))
    }
}

impl Lifecycle for ScimProvisioningPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| failure(error.to_string()))?;
        self.state.borrow_mut().replace(PreparedScim { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.state.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

async fn resolve_secret(
    secrets: &secrets::SecretsClient,
    dependencies: &lenso_kernel::PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            secrets::ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            secrets::SecretsInvocationError::Domain(_) => {
                failure(format!("SCIM database secret `{reference}` was rejected"))
            }
            secrets::SecretsInvocationError::Runtime(error) => error,
        })
}

mod http;

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ScimProvisioningConfig {
        ScimProvisioningConfig {
            schema: "scim_directory".to_owned(),
            database_url_secret: "scim/database-url".to_owned(),
            organization_id: "org_acme".to_owned(),
            identity_provider: "scim".to_owned(),
            directory_callers: vec!["app.scim-admin".to_owned()],
            repair_callers: vec!["worker.scim-repair".to_owned()],
            http_callers: vec!["web.scim".to_owned()],
            accepted_actor_kinds: vec!["service_account".to_owned()],
            required_organization_claim: "organization_id".to_owned(),
            max_page_size: 100,
            max_group_members: 1_000,
        }
    }

    #[test]
    fn immutable_configuration_requires_exact_service_account_boundary() {
        assert_eq!(config().validate(), Ok(()));
        let mut invalid = config();
        invalid.accepted_actor_kinds = vec!["user".to_owned()];
        assert_eq!(invalid.validate(), Err(ConfigError::SecurityBoundary));
        let mut invalid = config();
        invalid.http_callers.push("web.scim".to_owned());
        assert_eq!(invalid.validate(), Err(ConfigError::Callers));
    }

    #[test]
    fn filters_are_exact_bounded_eq_expressions() {
        assert_eq!(
            parse_filter(Some("userName eq \"ada@example.test\""), &["userName"])
                .unwrap()
                .unwrap()
                .value,
            "ada@example.test"
        );
        assert_eq!(
            parse_filter(Some("userName co \"ada\""), &["userName"]),
            Err(DirectoryFailure::InvalidRequest)
        );
        assert_eq!(
            parse_filter(Some("displayName eq \"Ada\""), &["userName"]),
            Err(DirectoryFailure::InvalidRequest)
        );
    }

    #[test]
    fn derived_resource_ids_are_stable_and_caller_scoped() {
        let first = stable_resource_id("usr", "caller-a", "key-1");
        assert_eq!(first, stable_resource_id("usr", "caller-a", "key-1"));
        assert_ne!(first, stable_resource_id("usr", "caller-b", "key-1"));
        assert!(first.starts_with("usr_"));
    }

    #[test]
    fn migration_owns_only_scim_state() {
        let migration = include_str!("../migrations/001_create_scim_directory.sql");
        for table in [
            "scim_users",
            "scim_groups",
            "scim_group_members",
            "scim_sync_receipts",
            "scim_membership_projection",
            "scim_role_projection",
        ] {
            assert!(migration.contains(&format!("CREATE TABLE {table}")));
        }
        for forbidden in [
            "identities",
            "organizations",
            "memberships",
            "roles",
            "role_bindings",
        ] {
            assert!(!migration.contains(&format!("CREATE TABLE {forbidden}")));
        }
    }
}
