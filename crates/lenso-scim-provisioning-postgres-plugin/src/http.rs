use super::*;

use lenso_capability_http_endpoint::{
    EndpointHandleInvocationError, HandleRequest, HandleResponse, HandleResponseHeadersItem,
    endpoint,
};
use serde::de::DeserializeOwned;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const GROUP_ROLE_SCHEMA: &str = "urn:lenso:params:scim:schemas:extension:rbac:2.0:Group";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UserInput {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(default, rename = "id")]
    _id: Option<String>,
    #[serde(default, rename = "meta")]
    _meta: Option<Value>,
    #[serde(default)]
    external_id: Option<String>,
    user_name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    emails: Vec<EmailInput>,
    #[serde(default = "default_true")]
    active: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmailInput {
    value: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    r#type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupInput {
    #[serde(default)]
    schemas: Vec<String>,
    #[serde(default, rename = "id")]
    _id: Option<String>,
    #[serde(default, rename = "meta")]
    _meta: Option<Value>,
    #[serde(default)]
    external_id: Option<String>,
    display_name: String,
    #[serde(default)]
    members: Vec<MemberInput>,
    #[serde(
        default,
        rename = "urn:lenso:params:scim:schemas:extension:rbac:2.0:Group"
    )]
    rbac: Option<GroupRbacInput>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MemberInput {
    value: String,
    #[serde(default, rename = "$ref")]
    _reference: Option<String>,
    #[serde(default, rename = "display")]
    _display: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GroupRbacInput {
    #[serde(default)]
    role_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchDocument {
    schemas: Vec<String>,
    #[serde(rename = "Operations")]
    operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchOperation {
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Option<Value>,
}

#[derive(Clone, Debug)]
struct AuthenticatedHttp {
    context: InvocationContext,
    receipt_caller: String,
}

enum HttpAccessFailure {
    Response(HandleResponse),
    Runtime(RuntimeFailure),
}

impl ScimProvisioningPlugin {
    async fn authenticate_http(
        &self,
        context: InvocationContext,
        request: &HandleRequest,
    ) -> Result<AuthenticatedHttp, HttpAccessFailure> {
        let Some(instance) = context.caller_instance().map(str::to_owned) else {
            return Err(HttpAccessFailure::Response(scim_error(
                403,
                None,
                "The HTTP caller Instance is not authorized for this SCIM endpoint.",
            )));
        };
        if !self
            .config
            .http_callers
            .iter()
            .any(|allowed| allowed == &instance)
        {
            return Err(HttpAccessFailure::Response(scim_error(
                403,
                None,
                "The HTTP caller Instance is not authorized for this SCIM endpoint.",
            )));
        }
        let evidence = request.credential.as_ref().and_then(|credential| {
            credential
                .scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| CredentialEvidence::new("bearer", credential.value.clone()))
        });
        let response =
            self.auth
                .authenticate_with_context(context.clone(), authenticate_request(evidence))
                .await
                .map_err(|error| match error {
                    auth::AuthInvocationError::Domain(_) => HttpAccessFailure::Response(
                        scim_error(401, None, "The bearer credential was rejected."),
                    ),
                    auth::AuthInvocationError::Runtime(error) => HttpAccessFailure::Runtime(error),
                })?;
        let outcome = decode_auth_response(response).map_err(|_| {
            HttpAccessFailure::Runtime(RuntimeFailure::Internal {
                detail: "Auth returned an inconsistent SCIM bearer outcome".to_owned(),
            })
        })?;
        let AuthOutcome::Authenticated(assertion) = outcome else {
            return Err(HttpAccessFailure::Response(scim_error(
                401,
                None,
                "A bearer credential is required.",
            )));
        };
        let claims = assertion.to_wire().claims.unwrap_or_default();
        let organization_matches = claims
            .get(&self.config.required_organization_claim)
            .and_then(Value::as_str)
            == Some(self.config.organization_id.as_str());
        if assertion.actor_kind() != "service_account"
            || !organization_matches
            || !valid_name(assertion.subject(), 256)
        {
            return Err(HttpAccessFailure::Response(scim_error(
                403,
                None,
                "The bearer token is not an organization-scoped service account.",
            )));
        }
        let receipt_caller = format!("http:{instance}:{}", assertion.subject());
        let context = assertion.attach(context).map_err(|_| {
            HttpAccessFailure::Runtime(RuntimeFailure::Internal {
                detail: "SCIM could not attach the authenticated Actor assertion".to_owned(),
            })
        })?;
        Ok(AuthenticatedHttp {
            context,
            receipt_caller,
        })
    }
}

fn access_result(
    result: Result<AuthenticatedHttp, HttpAccessFailure>,
) -> Result<Result<AuthenticatedHttp, HandleResponse>, EndpointHandleInvocationError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(HttpAccessFailure::Response(response)) => Ok(Err(response)),
        Err(HttpAccessFailure::Runtime(error)) => {
            Err(EndpointHandleInvocationError::Runtime(error))
        }
    }
}

fn directory_result(
    result: DirectoryResult<Value>,
) -> Result<Result<Value, HandleResponse>, EndpointHandleInvocationError> {
    match result {
        Ok(Ok(value)) => Ok(Ok(value)),
        Ok(Err(error)) => Ok(Err(directory_error_response(error))),
        Err(error) => Err(EndpointHandleInvocationError::Runtime(error)),
    }
}

fn directory_error_response(error: DirectoryFailure) -> HandleResponse {
    match error {
        DirectoryFailure::Unauthorized => scim_error(401, None, "Authentication is required."),
        DirectoryFailure::InvalidRequest => {
            scim_error(400, Some("invalidValue"), "The SCIM request is invalid.")
        }
        DirectoryFailure::NotFound => scim_error(404, None, "The SCIM resource was not found."),
        DirectoryFailure::Conflict => scim_error(
            409,
            Some("uniqueness"),
            "The SCIM resource or idempotency key conflicts.",
        ),
        DirectoryFailure::PreconditionFailed => scim_error(
            412,
            Some("versionMismatch"),
            "The SCIM resource version does not match If-Match.",
        ),
        DirectoryFailure::DownstreamRejected => scim_error(
            502,
            None,
            "An authoritative downstream provider rejected synchronization.",
        ),
    }
}

fn scim_error(status: i64, scim_type: Option<&str>, detail: &str) -> HandleResponse {
    let mut body = json!({"schemas":[ERROR_SCHEMA],"status":status.to_string(),"detail":detail});
    if let Some(scim_type) = scim_type {
        body["scimType"] = Value::String(scim_type.to_owned());
    }
    scim_json(status, &body, None, None)
}

fn scim_json(
    status: i64,
    body: &Value,
    etag: Option<&str>,
    location: Option<&str>,
) -> HandleResponse {
    let mut headers = vec![HandleResponseHeadersItem {
        name: "content-type".to_owned(),
        value: SCIM_CONTENT_TYPE.to_owned(),
    }];
    if let Some(etag) = etag {
        headers.push(HandleResponseHeadersItem {
            name: "etag".to_owned(),
            value: format!("W/\"{etag}\""),
        });
    }
    if let Some(location) = location {
        headers.push(HandleResponseHeadersItem {
            name: "location".to_owned(),
            value: location.to_owned(),
        });
    }
    HandleResponse {
        body: serde_json::to_vec(body)
            .expect("JSON Value serialization cannot fail")
            .into(),
        headers,
        status,
    }
}

fn empty_scim(status: i64, etag: Option<&str>) -> HandleResponse {
    let headers = etag.map_or_else(Vec::new, |etag| {
        vec![HandleResponseHeadersItem {
            name: "etag".to_owned(),
            value: format!("W/\"{etag}\""),
        }]
    });
    HandleResponse {
        body: Vec::new().into(),
        headers,
        status,
    }
}

fn json_body<T: DeserializeOwned>(request: &HandleRequest) -> Result<T, HandleResponse> {
    if request.body.as_slice().len() > 1_048_576 {
        return Err(scim_error(
            413,
            Some("tooLarge"),
            "The SCIM request body exceeds one MiB.",
        ));
    }
    serde_json::from_slice(request.body.as_slice())
        .map_err(|_| scim_error(400, Some("invalidSyntax"), "The SCIM JSON body is invalid."))
}

fn header<'a>(request: &'a HandleRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn path_id(request: &HandleRequest) -> Result<String, HandleResponse> {
    request
        .path_parameters
        .iter()
        .find(|parameter| parameter.name == "id")
        .map(|parameter| parameter.value.clone())
        .filter(|value| valid_name(value, 256))
        .ok_or_else(|| {
            scim_error(
                400,
                Some("invalidPath"),
                "The SCIM resource path is invalid.",
            )
        })
}

fn expected_version(request: &HandleRequest) -> Result<String, HandleResponse> {
    let Some(value) = header(request, "if-match") else {
        return Err(scim_error(
            428,
            None,
            "If-Match is required for SCIM mutations.",
        ));
    };
    let value = value.strip_prefix("W/").unwrap_or(value);
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    parse_revision(Some(value))
        .map(|version| version.to_string())
        .ok_or_else(|| {
            scim_error(
                400,
                Some("invalidValue"),
                "If-Match must contain a positive SCIM version.",
            )
        })
}

fn idempotency_key(request: &HandleRequest) -> Result<String, HandleResponse> {
    let value = header(request, "idempotency-key").unwrap_or(&request.request_id);
    valid_name(value, 256)
        .then(|| value.to_owned())
        .ok_or_else(|| {
            scim_error(
                400,
                Some("invalidValue"),
                "A bounded Idempotency-Key or request_id is required.",
            )
        })
}

fn cast<T: DeserializeOwned>(value: impl Serialize) -> Result<T, HandleResponse> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|_| {
            scim_error(
                400,
                Some("invalidValue"),
                "The SCIM representation has an invalid field.",
            )
        })
}

fn default_true() -> bool {
    true
}

fn user_scim(value: &Value) -> Value {
    let id = value.get("id").and_then(Value::as_str).unwrap_or_default();
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "schemas":[USER_SCHEMA],
        "id":id,
        "externalId":value.get("external_id").cloned().unwrap_or(Value::Null),
        "userName":value.get("user_name").cloned().unwrap_or(Value::Null),
        "displayName":value.get("display_name").cloned().unwrap_or(Value::Null),
        "emails":value.get("emails").cloned().unwrap_or_else(|| json!([])),
        "active":value.get("active").cloned().unwrap_or(Value::Bool(false)),
        "meta":{
            "resourceType":"User",
            "created":value.get("created_at").cloned().unwrap_or(Value::Null),
            "lastModified":value.get("updated_at").cloned().unwrap_or(Value::Null),
            "version":format!("W/\"{version}\""),
            "location":format!("/scim/v2/Users/{id}")
        }
    })
}

fn group_scim(value: &Value) -> Value {
    let id = value.get("id").and_then(Value::as_str).unwrap_or_default();
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let members = value
        .get("member_user_ids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|member| json!({"value":member,"$ref":format!("/scim/v2/Users/{member}")}))
        .collect::<Vec<_>>();
    json!({
        "schemas":[GROUP_SCHEMA,GROUP_ROLE_SCHEMA],
        "id":id,
        "externalId":value.get("external_id").cloned().unwrap_or(Value::Null),
        "displayName":value.get("display_name").cloned().unwrap_or(Value::Null),
        "members":members,
        GROUP_ROLE_SCHEMA:{"roleId":value.get("role_id").cloned().unwrap_or(Value::Null)},
        "meta":{
            "resourceType":"Group",
            "created":value.get("created_at").cloned().unwrap_or(Value::Null),
            "lastModified":value.get("updated_at").cloned().unwrap_or(Value::Null),
            "version":format!("W/\"{version}\""),
            "location":format!("/scim/v2/Groups/{id}")
        }
    })
}

fn list_scim(value: &Value, map: fn(&Value) -> Value) -> Value {
    let resources = value
        .get("resources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(map)
        .collect::<Vec<_>>();
    json!({
        "schemas":[LIST_SCHEMA],
        "totalResults":value.get("total_results").cloned().unwrap_or(json!(0)),
        "startIndex":value.get("start_index").cloned().unwrap_or(json!(1)),
        "itemsPerPage":resources.len(),
        "Resources":resources,
    })
}

fn list_request(
    request: &HandleRequest,
    organization_id: &str,
    maximum: i64,
) -> Result<(String, Option<String>, i64, i64), HandleResponse> {
    let mut filter = None;
    let mut start_index = 1_i64;
    let mut count = maximum.min(100);
    if let Some(query) = &request.query {
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match name.as_ref() {
                "filter" if filter.is_none() => filter = Some(value.into_owned()),
                "startIndex" => {
                    start_index = value.parse().map_err(|_| {
                        scim_error(400, Some("invalidValue"), "startIndex is invalid.")
                    })?;
                }
                "count" => {
                    count = value
                        .parse()
                        .map_err(|_| scim_error(400, Some("invalidValue"), "count is invalid."))?;
                }
                "attributes" | "excludedAttributes" => {}
                _ => {
                    return Err(scim_error(
                        400,
                        Some("invalidValue"),
                        "The SCIM query contains an unsupported or duplicate parameter.",
                    ));
                }
            }
        }
    }
    if start_index < 1 || count < 1 || count > maximum {
        return Err(scim_error(
            400,
            Some("invalidValue"),
            "SCIM pagination is outside configured bounds.",
        ));
    }
    Ok((organization_id.to_owned(), filter, start_index, count))
}

fn version_of(value: &Value) -> Option<&str> {
    value.get("version").and_then(Value::as_str)
}

fn user_patch_request(
    request: &HandleRequest,
    organization_id: &str,
    resource_id: String,
) -> Result<scim::PatchUserRequest, HandleResponse> {
    let document: PatchDocument = json_body(request)?;
    if document.schemas != [PATCH_SCHEMA]
        || document.operations.is_empty()
        || document.operations.len() > 100
    {
        return Err(scim_error(
            400,
            Some("invalidSyntax"),
            "A SCIM PatchOp document with bounded Operations is required.",
        ));
    }
    let mut output = scim::PatchUserRequest {
        active: None,
        display_name: None,
        emails: None,
        expected_version: expected_version(request)?,
        external_id: None,
        idempotency_key: idempotency_key(request)?,
        organization_id: organization_id.to_owned(),
        remove_fields: None,
        resource_id,
        user_name: None,
    };
    let mut removes = Vec::new();
    for operation in document.operations {
        let op = operation.op.to_ascii_lowercase();
        let path = operation.path.as_deref();
        if path.is_none() && matches!(op.as_str(), "add" | "replace") {
            let value = operation
                .value
                .and_then(|value| value.as_object().cloned())
                .ok_or_else(|| {
                    scim_error(
                        400,
                        Some("invalidValue"),
                        "A pathless user PATCH value must be an object.",
                    )
                })?;
            for (field, value) in value {
                apply_user_patch_field(&mut output, &mut removes, &op, &field, Some(value))?;
            }
        } else {
            let path = path.ok_or_else(|| {
                scim_error(
                    400,
                    Some("noTarget"),
                    "The SCIM PATCH operation requires a path.",
                )
            })?;
            apply_user_patch_field(&mut output, &mut removes, &op, path, operation.value)?;
        }
    }
    if !removes.is_empty() {
        output.remove_fields = Some(removes);
    }
    Ok(output)
}

fn apply_user_patch_field(
    output: &mut scim::PatchUserRequest,
    removes: &mut Vec<scim::PatchUserRequestRemoveFieldsItem>,
    op: &str,
    path: &str,
    value: Option<Value>,
) -> Result<(), HandleResponse> {
    match (op, path) {
        ("remove", "externalId") => {
            removes.push(scim::PatchUserRequestRemoveFieldsItem::ExternalId);
        }
        ("remove", "displayName") => {
            removes.push(scim::PatchUserRequestRemoveFieldsItem::DisplayName);
        }
        ("remove", "emails") => removes.push(scim::PatchUserRequestRemoveFieldsItem::Emails),
        ("add" | "replace", "externalId") => {
            output.external_id = Some(required_string(value, path)?);
        }
        ("add" | "replace", "userName") => output.user_name = Some(required_string(value, path)?),
        ("add" | "replace", "displayName") => {
            output.display_name = Some(required_string(value, path)?);
        }
        ("add" | "replace", "active") => {
            output.active =
                Some(value.and_then(|value| value.as_bool()).ok_or_else(|| {
                    scim_error(400, Some("invalidValue"), "active must be boolean.")
                })?);
        }
        ("add" | "replace", "emails") => {
            output.emails = Some(cast::<Vec<scim::PatchUserRequestEmailsItem>>(
                value.ok_or_else(|| {
                    scim_error(400, Some("invalidValue"), "emails requires a value.")
                })?,
            )?);
        }
        _ => {
            return Err(scim_error(
                400,
                Some("invalidPath"),
                "The user PATCH path or operation is unsupported.",
            ));
        }
    }
    Ok(())
}

fn group_patch_request(
    request: &HandleRequest,
    organization_id: &str,
    resource_id: String,
) -> Result<scim::PatchGroupRequest, HandleResponse> {
    let document: PatchDocument = json_body(request)?;
    if document.schemas != [PATCH_SCHEMA]
        || document.operations.is_empty()
        || document.operations.len() > 100
    {
        return Err(scim_error(
            400,
            Some("invalidSyntax"),
            "A SCIM PatchOp document with bounded Operations is required.",
        ));
    }
    let mut output = scim::PatchGroupRequest {
        display_name: None,
        expected_version: expected_version(request)?,
        external_id: None,
        idempotency_key: idempotency_key(request)?,
        members_add: None,
        members_remove: None,
        organization_id: organization_id.to_owned(),
        remove_external_id: None,
        remove_role: None,
        resource_id,
        role_id: None,
    };
    let mut add = BTreeSet::new();
    let mut remove = BTreeSet::new();
    for operation in document.operations {
        let op = operation.op.to_ascii_lowercase();
        let path = operation.path.unwrap_or_default();
        match (op.as_str(), path.as_str()) {
            ("add" | "replace", "displayName") => {
                output.display_name = Some(required_string(operation.value, "displayName")?);
            }
            ("add" | "replace", "externalId") => {
                output.external_id = Some(required_string(operation.value, "externalId")?);
            }
            ("remove", "externalId") => {
                output.remove_external_id = Some(true);
            }
            ("add" | "replace", p)
                if p == format!("{GROUP_ROLE_SCHEMA}:roleId") || p == "roleId" =>
            {
                output.role_id = Some(required_string(operation.value, "roleId")?);
            }
            ("remove", p) if p == format!("{GROUP_ROLE_SCHEMA}:roleId") || p == "roleId" => {
                output.remove_role = Some(true);
            }
            ("add", "members") => {
                for member in parse_member_values(operation.value)? {
                    add.insert(member);
                }
            }
            ("remove", filter)
                if filter.starts_with("members[value eq \"") && filter.ends_with("\"]") =>
            {
                let value = &filter[18..filter.len() - 2];
                if !valid_name(value, 256) {
                    return Err(scim_error(
                        400,
                        Some("invalidFilter"),
                        "The member removal filter is invalid.",
                    ));
                }
                remove.insert(value.to_owned());
            }
            _ => {
                return Err(scim_error(
                    400,
                    Some("invalidPath"),
                    "The group PATCH path or operation is unsupported.",
                ));
            }
        }
    }
    if !add.is_empty() {
        output.members_add = Some(add.into_iter().collect());
    }
    if !remove.is_empty() {
        output.members_remove = Some(remove.into_iter().collect());
    }
    Ok(output)
}

fn required_string(value: Option<Value>, field: &str) -> Result<String, HandleResponse> {
    value
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|value| valid_name(value, 512))
        .ok_or_else(|| {
            scim_error(
                400,
                Some("invalidValue"),
                &format!("{field} requires a non-empty string."),
            )
        })
}

fn parse_member_values(value: Option<Value>) -> Result<Vec<String>, HandleResponse> {
    let value =
        value.ok_or_else(|| scim_error(400, Some("invalidValue"), "members requires a value."))?;
    let values = if value.is_array() {
        value
    } else {
        json!([value])
    };
    let members: Vec<MemberInput> = cast(values)?;
    if !unique_valid_ids(
        &members
            .iter()
            .map(|member| member.value.clone())
            .collect::<Vec<_>>(),
    ) {
        return Err(scim_error(
            400,
            Some("invalidValue"),
            "members must contain unique valid user IDs.",
        ));
    }
    Ok(members.into_iter().map(|member| member.value).collect())
}

#[endpoint]
impl ScimProvisioningPlugin {
    #[get("scim.service-provider-config", "/scim/v2/ServiceProviderConfig")]
    async fn service_provider_config(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if let Err(response) = access_result(self.authenticate_http(context, &request).await)? {
            return Ok(response);
        }
        Ok(scim_json(
            200,
            &json!({
                "schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "documentationUri":"https://github.com/LioRael/lenso-scim-provisioning-plugin/blob/main/docs/operator-guide.md",
                "patch":{"supported":true},
                "bulk":{"supported":false,"maxOperations":0,"maxPayloadSize":0},
                "filter":{"supported":true,"maxResults":self.config.max_page_size},
                "changePassword":{"supported":false},
                "sort":{"supported":false},
                "etag":{"supported":true},
                "authenticationSchemes":[{"type":"oauthbearertoken","name":"Bearer token","description":"Organization-scoped Lenso service-account token","specUri":"https://www.rfc-editor.org/rfc/rfc6750"}]
            }),
            None,
            None,
        ))
    }

    #[get("scim.resource-types", "/scim/v2/ResourceTypes")]
    async fn resource_types(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if let Err(response) = access_result(self.authenticate_http(context, &request).await)? {
            return Ok(response);
        }
        Ok(scim_json(
            200,
            &json!({
                "schemas":[LIST_SCHEMA],"totalResults":2,"startIndex":1,"itemsPerPage":2,
                "Resources":[
                    {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"User","name":"User","endpoint":"/Users","schema":USER_SCHEMA},
                    {"schemas":["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],"id":"Group","name":"Group","endpoint":"/Groups","schema":GROUP_SCHEMA,"schemaExtensions":[{"schema":GROUP_ROLE_SCHEMA,"required":false}]}
                ]
            }),
            None,
            None,
        ))
    }

    #[get("scim.schemas", "/scim/v2/Schemas")]
    async fn schemas(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if let Err(response) = access_result(self.authenticate_http(context, &request).await)? {
            return Ok(response);
        }
        Ok(scim_json(
            200,
            &json!({
                "schemas":[LIST_SCHEMA],"totalResults":3,"startIndex":1,"itemsPerPage":3,
                "Resources":[
                    {"id":USER_SCHEMA,"name":"User","description":"Lenso organization-local SCIM user","attributes":[
                        {"name":"userName","type":"string","multiValued":false,"required":true,"uniqueness":"server"},
                        {"name":"externalId","type":"string","multiValued":false,"required":false,"uniqueness":"server"},
                        {"name":"displayName","type":"string","multiValued":false,"required":false},
                        {"name":"emails","type":"complex","multiValued":true,"required":false},
                        {"name":"active","type":"boolean","multiValued":false,"required":true}
                    ]},
                    {"id":GROUP_SCHEMA,"name":"Group","description":"Lenso SCIM group","attributes":[
                        {"name":"displayName","type":"string","multiValued":false,"required":true,"uniqueness":"server"},
                        {"name":"externalId","type":"string","multiValued":false,"required":false,"uniqueness":"server"},
                        {"name":"members","type":"complex","multiValued":true,"required":false}
                    ]},
                    {"id":GROUP_ROLE_SCHEMA,"name":"Lenso RBAC Group","description":"Maps one SCIM group to one organization RBAC role","attributes":[{"name":"roleId","type":"string","multiValued":false,"required":false}]}
                ]
            }),
            None,
            None,
        ))
    }

    #[get("scim.users.list", "/scim/v2/Users")]
    async fn users_list(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let (organization_id, filter, start_index, count) = match list_request(
            &request,
            &self.config.organization_id,
            self.config.max_page_size,
        ) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.list_users_value(scim::ListUsersRequest {
                organization_id,
                filter,
                start_index,
                count,
            })
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        drop(auth);
        Ok(scim_json(200, &list_scim(&value, user_scim), None, None))
    }

    #[post("scim.users.create", "/scim/v2/Users")]
    async fn users_create(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let input: UserInput = match json_body(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if input.schemas != [USER_SCHEMA] {
            return Ok(scim_error(
                400,
                Some("invalidSyntax"),
                "The User schemas field is invalid.",
            ));
        }
        let emails = match cast(input.emails) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let request_id = match idempotency_key(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.create_user_value(
                &auth.context,
                &auth.receipt_caller,
                scim::CreateUserRequest {
                    active: input.active,
                    display_name: input.display_name,
                    emails,
                    expected_version: None,
                    external_id: input.external_id,
                    idempotency_key: request_id,
                    organization_id: self.config.organization_id.clone(),
                    resource_id: None,
                    user_name: input.user_name,
                },
            )
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let body = user_scim(&value);
        let id = value.get("id").and_then(Value::as_str).unwrap_or_default();
        Ok(scim_json(
            201,
            &body,
            version_of(&value),
            Some(&format!("/scim/v2/Users/{id}")),
        ))
    }

    #[get("scim.users.get", "/scim/v2/Users/{id}")]
    async fn users_get(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if let Err(response) = access_result(self.authenticate_http(context, &request).await)? {
            return Ok(response);
        }
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.load_user_value(&self.config.organization_id, &id, false)
                .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(200, &user_scim(&value), version_of(&value), None))
    }

    #[put("scim.users.replace", "/scim/v2/Users/{id}")]
    async fn users_replace(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let expected = match expected_version(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let key = match idempotency_key(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let input: UserInput = match json_body(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if input.schemas != [USER_SCHEMA] {
            return Ok(scim_error(
                400,
                Some("invalidSyntax"),
                "The User schemas field is invalid.",
            ));
        }
        let emails = match cast(input.emails) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.replace_user_value(
                &auth.context,
                &auth.receipt_caller,
                scim::ReplaceUserRequest {
                    active: input.active,
                    display_name: input.display_name,
                    emails,
                    expected_version: Some(expected),
                    external_id: input.external_id,
                    idempotency_key: key,
                    organization_id: self.config.organization_id.clone(),
                    resource_id: Some(id),
                    user_name: input.user_name,
                },
            )
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(200, &user_scim(&value), version_of(&value), None))
    }

    #[patch("scim.users.patch", "/scim/v2/Users/{id}")]
    async fn users_patch(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let patch = match user_patch_request(&request, &self.config.organization_id, id) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.patch_user_value(&auth.context, &auth.receipt_caller, patch)
                .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(200, &user_scim(&value), version_of(&value), None))
    }

    #[delete("scim.users.delete", "/scim/v2/Users/{id}")]
    async fn users_delete(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let expected = match expected_version(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let key = match idempotency_key(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.delete_user_value(
                &auth.context,
                &auth.receipt_caller,
                scim::DeleteUserRequest {
                    expected_version: expected,
                    idempotency_key: key,
                    organization_id: self.config.organization_id.clone(),
                    resource_id: id,
                },
            )
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(empty_scim(204, version_of(&value)))
    }

    #[get("scim.groups.list", "/scim/v2/Groups")]
    async fn groups_list(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let _auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let (organization_id, filter, start_index, count) = match list_request(
            &request,
            &self.config.organization_id,
            self.config.max_page_size,
        ) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.list_groups_value(scim::ListGroupsRequest {
                organization_id,
                filter,
                start_index,
                count,
            })
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(200, &list_scim(&value, group_scim), None, None))
    }

    #[post("scim.groups.create", "/scim/v2/Groups")]
    async fn groups_create(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let input: GroupInput = match json_body(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if !valid_group_schemas(&input.schemas) {
            return Ok(scim_error(
                400,
                Some("invalidSyntax"),
                "The Group schemas field is invalid.",
            ));
        }
        let members = input
            .members
            .into_iter()
            .map(|member| member.value)
            .collect::<Vec<_>>();
        let key = match idempotency_key(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.create_group_value(
                &auth.context,
                &auth.receipt_caller,
                scim::CreateGroupRequest {
                    display_name: input.display_name,
                    expected_version: None,
                    external_id: input.external_id,
                    idempotency_key: key,
                    member_user_ids: members,
                    organization_id: self.config.organization_id.clone(),
                    resource_id: None,
                    role_id: input.rbac.and_then(|rbac| rbac.role_id),
                },
            )
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let body = group_scim(&value);
        let id = value.get("id").and_then(Value::as_str).unwrap_or_default();
        Ok(scim_json(
            201,
            &body,
            version_of(&value),
            Some(&format!("/scim/v2/Groups/{id}")),
        ))
    }

    #[get("scim.groups.get", "/scim/v2/Groups/{id}")]
    async fn groups_get(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        if let Err(response) = access_result(self.authenticate_http(context, &request).await)? {
            return Ok(response);
        }
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.load_group_value(&self.config.organization_id, &id, false)
                .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(
            200,
            &group_scim(&value),
            version_of(&value),
            None,
        ))
    }

    #[put("scim.groups.replace", "/scim/v2/Groups/{id}")]
    async fn groups_replace(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let expected = match expected_version(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let key = match idempotency_key(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let input: GroupInput = match json_body(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        if !valid_group_schemas(&input.schemas) {
            return Ok(scim_error(
                400,
                Some("invalidSyntax"),
                "The Group schemas field is invalid.",
            ));
        }
        let value = match directory_result(
            self.replace_group_value(
                &auth.context,
                &auth.receipt_caller,
                scim::ReplaceGroupRequest {
                    display_name: input.display_name,
                    expected_version: Some(expected),
                    external_id: input.external_id,
                    idempotency_key: key,
                    member_user_ids: input
                        .members
                        .into_iter()
                        .map(|member| member.value)
                        .collect(),
                    organization_id: self.config.organization_id.clone(),
                    resource_id: Some(id),
                    role_id: input.rbac.and_then(|rbac| rbac.role_id),
                },
            )
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(
            200,
            &group_scim(&value),
            version_of(&value),
            None,
        ))
    }

    #[patch("scim.groups.patch", "/scim/v2/Groups/{id}")]
    async fn groups_patch(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let patch = match group_patch_request(&request, &self.config.organization_id, id) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.patch_group_value(&auth.context, &auth.receipt_caller, patch)
                .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(scim_json(
            200,
            &group_scim(&value),
            version_of(&value),
            None,
        ))
    }

    #[delete("scim.groups.delete", "/scim/v2/Groups/{id}")]
    async fn groups_delete(
        &self,
        context: InvocationContext,
        request: HandleRequest,
    ) -> Result<HandleResponse, EndpointHandleInvocationError> {
        let auth = match access_result(self.authenticate_http(context, &request).await)? {
            Ok(auth) => auth,
            Err(response) => return Ok(response),
        };
        let id = match path_id(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let expected = match expected_version(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let key = match idempotency_key(&request) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let value = match directory_result(
            self.delete_group_value(
                &auth.context,
                &auth.receipt_caller,
                scim::DeleteGroupRequest {
                    expected_version: expected,
                    idempotency_key: key,
                    organization_id: self.config.organization_id.clone(),
                    resource_id: id,
                },
            )
            .await,
        )? {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        Ok(empty_scim(204, version_of(&value)))
    }
}

fn valid_group_schemas(schemas: &[String]) -> bool {
    (schemas == [GROUP_SCHEMA] || schemas == [GROUP_SCHEMA, GROUP_ROLE_SCHEMA])
        && schemas.iter().collect::<BTreeSet<_>>().len() == schemas.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: &Value) -> HandleRequest {
        HandleRequest {
            body: serde_json::to_vec(body).unwrap().into(),
            credential: None,
            headers: vec![
                lenso_capability_http_endpoint::HandleRequestHeadersItem {
                    name: "If-Match".to_owned(),
                    value: "W/\"7\"".to_owned(),
                },
                lenso_capability_http_endpoint::HandleRequestHeadersItem {
                    name: "Idempotency-Key".to_owned(),
                    value: "request-7".to_owned(),
                },
            ],
            method: "PATCH".to_owned(),
            path: "/scim/v2/Users/usr_ada".to_owned(),
            path_parameters: vec![
                lenso_capability_http_endpoint::HandleRequestPathParametersItem {
                    name: "id".to_owned(),
                    value: "usr_ada".to_owned(),
                },
            ],
            query: None,
            request_id: "ingress-7".to_owned(),
            route_id: "scim.users.patch".to_owned(),
        }
    }

    #[test]
    fn user_patch_lowers_rfc_patch_fields_and_precondition() {
        let request = request(&json!({
            "schemas":[PATCH_SCHEMA],
            "Operations":[
                {"op":"replace","path":"active","value":false},
                {"op":"remove","path":"emails"},
                {"op":"replace","path":"externalId","value":"external-ada"}
            ]
        }));
        let patch = user_patch_request(&request, "org_acme", "usr_ada".to_owned()).unwrap();
        assert_eq!(patch.expected_version, "7");
        assert_eq!(patch.idempotency_key, "request-7");
        assert_eq!(patch.active, Some(false));
        assert_eq!(patch.external_id.as_deref(), Some("external-ada"));
        assert_eq!(
            patch.remove_fields,
            Some(vec![scim::PatchUserRequestRemoveFieldsItem::Emails])
        );
    }

    #[test]
    fn group_representation_uses_the_rbac_extension_uri() {
        let value = group_scim(&json!({
            "id":"grp_engineering","organization_id":"org_acme","external_id":null,
            "display_name":"Engineering","member_user_ids":["usr_ada"],"role_id":"engineer",
            "version":"3","created_at":"2026-08-31T00:00:00Z","updated_at":"2026-08-31T00:00:01Z","sync_status":"converged"
        }));
        assert_eq!(value[GROUP_ROLE_SCHEMA]["roleId"], "engineer");
        assert_eq!(value["members"][0]["value"], "usr_ada");
        assert_eq!(value["meta"]["version"], "W/\"3\"");
    }

    #[test]
    fn error_responses_use_scim_media_type_and_error_schema() {
        let response = scim_error(412, Some("versionMismatch"), "stale");
        assert_eq!(response.status, 412);
        assert_eq!(response.headers[0].value, SCIM_CONTENT_TYPE);
        let body: Value = serde_json::from_slice(response.body.as_slice()).unwrap();
        assert_eq!(body["schemas"][0], ERROR_SCHEMA);
        assert_eq!(body["scimType"], "versionMismatch");
    }
}
