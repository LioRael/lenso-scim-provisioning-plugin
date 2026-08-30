CREATE TABLE scim_users (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    external_id text,
    user_name text NOT NULL,
    display_name text,
    emails jsonb NOT NULL,
    active boolean NOT NULL,
    subject text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    sync_status text NOT NULL CHECK (sync_status IN ('converged', 'pending')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz
);

CREATE TABLE scim_groups (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    external_id text,
    display_name text NOT NULL,
    role_id text,
    version bigint NOT NULL CHECK (version > 0),
    sync_status text NOT NULL CHECK (sync_status IN ('converged', 'pending')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    deleted_at timestamptz
);

CREATE TABLE scim_group_members (
    group_id text NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES scim_users(id),
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE scim_sync_receipts (
    caller_instance text NOT NULL,
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash bytea NOT NULL,
    organization_id text NOT NULL,
    resource_type text NOT NULL,
    resource_id text,
    status text NOT NULL CHECK (status IN ('in_progress', 'pending', 'completed', 'failed')),
    step text NOT NULL,
    error_code text,
    request_json jsonb NOT NULL,
    result_json jsonb,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (caller_instance, operation, idempotency_key)
);

CREATE TABLE scim_membership_projection (
    user_id text PRIMARY KEY REFERENCES scim_users(id),
    subject text NOT NULL,
    desired boolean NOT NULL,
    applied boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE scim_role_projection (
    group_id text NOT NULL REFERENCES scim_groups(id),
    user_id text NOT NULL REFERENCES scim_users(id),
    subject text NOT NULL,
    role_id text NOT NULL,
    desired boolean NOT NULL,
    applied boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (group_id, user_id, role_id)
);

CREATE INDEX scim_users_active_idx
    ON scim_users (organization_id, id)
    WHERE deleted_at IS NULL;
CREATE INDEX scim_groups_active_idx
    ON scim_groups (organization_id, id)
    WHERE deleted_at IS NULL;
CREATE INDEX scim_sync_pending_idx
    ON scim_sync_receipts (organization_id, updated_at)
    WHERE status = 'pending';
CREATE UNIQUE INDEX scim_users_name_unique_idx
    ON scim_users (organization_id, user_name)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX scim_users_external_unique_idx
    ON scim_users (organization_id, external_id)
    WHERE deleted_at IS NULL AND external_id IS NOT NULL;
CREATE UNIQUE INDEX scim_groups_name_unique_idx
    ON scim_groups (organization_id, display_name)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX scim_groups_external_unique_idx
    ON scim_groups (organization_id, external_id)
    WHERE deleted_at IS NULL AND external_id IS NOT NULL;
