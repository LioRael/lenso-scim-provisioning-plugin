use super::*;

use sqlx::AssertSqlSafe;

async fn prepare() -> Option<(String, String, OwnedPostgres)> {
    let database_url = std::env::var("LENSO_SCIM_TEST_DATABASE_URL").ok()?;
    let schema_name = format!("scim_acceptance_{}", uuid::Uuid::new_v4().simple());
    ScimProvisioningOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    ScimProvisioningOperator::upgrade(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    Some((database_url, schema_name, postgres))
}

async fn cleanup(database_url: &str, schema_name: &str, postgres: OwnedPostgres) {
    assert!(schema_name.starts_with("scim_acceptance_"));
    postgres.pool().close().await;
    let pool = sqlx::PgPool::connect(database_url).await.unwrap();
    sqlx::query(AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema_name}\" CASCADE"
    )))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

#[tokio::test]
async fn postgres_restart_uniqueness_cas_and_receipt_acceptance() {
    let Some((database_url, schema_name, postgres)) = prepare().await else {
        eprintln!("skipping PostgreSQL acceptance; LENSO_SCIM_TEST_DATABASE_URL is unset");
        return;
    };
    sqlx::query("INSERT INTO scim_users(id,organization_id,external_id,user_name,display_name,emails,active,subject,version,sync_status) VALUES('usr_ada','org_acme','ext_ada','ada@example.test','Ada','[]',true,'subject_ada',1,'pending')")
        .execute(postgres.pool()).await.unwrap();
    assert!(sqlx::query("INSERT INTO scim_users(id,organization_id,external_id,user_name,display_name,emails,active,subject,version,sync_status) VALUES('usr_duplicate','org_acme','ext_ada','other@example.test','Other','[]',true,'subject_other',1,'pending')")
        .execute(postgres.pool()).await.is_err());
    sqlx::query("INSERT INTO scim_membership_projection(user_id,subject,desired,applied) VALUES('usr_ada','subject_ada',true,false)")
        .execute(postgres.pool()).await.unwrap();
    let (left, right) = tokio::join!(
        sqlx::query("UPDATE scim_users SET display_name='Ada One',version=version+1 WHERE id='usr_ada' AND version=1").execute(postgres.pool()),
        sqlx::query("UPDATE scim_users SET display_name='Ada Two',version=version+1 WHERE id='usr_ada' AND version=1").execute(postgres.pool()),
    );
    assert_eq!(
        left.unwrap().rows_affected() + right.unwrap().rows_affected(),
        1
    );
    sqlx::query("INSERT INTO scim_sync_receipts(caller_instance,operation,idempotency_key,request_hash,organization_id,resource_type,resource_id,status,step,request_json) VALUES('web.scim','replace_user','request-1','\\x01','org_acme','user','usr_ada','pending','membership_pending','{}')")
        .execute(postgres.pool()).await.unwrap();
    assert!(sqlx::query("INSERT INTO scim_sync_receipts(caller_instance,operation,idempotency_key,request_hash,organization_id,resource_type,resource_id,status,step,request_json) VALUES('web.scim','replace_user','request-1','\\x02','org_acme','user','usr_ada','pending','membership_pending','{}')")
        .execute(postgres.pool()).await.is_err());

    postgres.pool().close().await;
    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let pending: bool = sqlx::query("SELECT desired<>applied AS pending FROM scim_membership_projection WHERE user_id='usr_ada'")
        .fetch_one(restarted.pool()).await.unwrap().try_get("pending").unwrap();
    assert!(pending);
    let receipt_count: i64 = sqlx::query("SELECT count(*) AS count FROM scim_sync_receipts")
        .fetch_one(restarted.pool())
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    assert_eq!(receipt_count, 1);
    cleanup(&database_url, &schema_name, restarted).await;
}
