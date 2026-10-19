use crate::{ControlError, flow::now_micros};
use broker_store::{
    schema::{Dialect, SchemaVersion, TABLES, Table},
    seeds::InitialSeeds,
    time::TimestampMicros,
};
use serde_json::Value;
use sqlx_core::{sql_str::AssertSqlSafe, transaction::Transaction};
use sqlx_postgres::{PgConnection, Postgres};

pub(crate) const STARTUP_LOCK: i64 = i64::from_be_bytes(*b"GBRKINIT");

async fn inventory(tx: &mut Transaction<'_, Postgres>) -> Result<Vec<String>, ControlError> {
    sqlx_core::query_scalar::query_scalar("SELECT c.relname::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname")
        .fetch_all(&mut **tx).await.map_err(|_| ControlError::SchemaRejected)
}

// The descriptor comes from PostgreSQL's own parsed DDL. Expected structures are TEMP
// copies of the exact producer DDL, not a second column/constraint/index model.
async fn shape(
    tx: &mut Transaction<'_, Postgres>,
    namespace: &str,
    table: Table,
) -> Result<Value, ControlError> {
    let result: sqlx_core::types::Json<Value> = sqlx_core::query_scalar::query_scalar(r#"
        SELECT pg_catalog.jsonb_build_object(
          'regular',c.relkind='r', 'private_owner',c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user),
          'rls',c.relrowsecurity, 'force_rls',c.relforcerowsecurity,
          'rules_ok',NOT EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=c.oid),
          'inherits',EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid),
          'triggers_ok',NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=c.oid AND (NOT tgisinternal OR tgenabled!='O')),
          'columns',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
              a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,
              a.attcollation::bigint,a.attidentity::text,a.attgenerated::text,
              pg_catalog.pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
              FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
              WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
          'constraints',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
              con.contype::text,con.conkey::smallint[],con.confkey::smallint[],target.relname,
              CASE WHEN con.contype='f' THEN target_ns.nspname=$1 ELSE true END,
              con.confupdtype::text,con.confdeltype::text,con.confmatchtype::text,
              con.condeferrable,con.condeferred,con.convalidated,con.conislocal,con.coninhcount,
              pg_catalog.pg_get_expr(con.conbin,con.conrelid)) ORDER BY con.conname)
              FROM pg_catalog.pg_constraint con LEFT JOIN pg_catalog.pg_class target ON target.oid=con.confrelid
              LEFT JOIN pg_catalog.pg_namespace target_ns ON target_ns.oid=target.relnamespace WHERE con.conrelid=c.oid),
          'indexes',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
              am.amname,i.indisunique,i.indisprimary,i.indisexclusion,i.indimmediate,
              i.indisvalid,i.indisready,i.indislive,i.indnullsnotdistinct,i.indnkeyatts,i.indnatts,
              i.indkey::smallint[],i.indclass::oid[],i.indcollation::oid[],i.indoption::smallint[],
              pg_catalog.pg_get_expr(i.indexprs,i.indrelid),pg_catalog.pg_get_expr(i.indpred,i.indrelid)) ORDER BY idx.relname)
              FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
              JOIN pg_catalog.pg_am am ON am.oid=idx.relam WHERE i.indrelid=c.oid)
        ) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=$1 AND c.relname=$2
    "#).bind(namespace).bind(table.name()).fetch_one(&mut **tx).await.map_err(|_| ControlError::SchemaRejected)?;
    Ok(result.0)
}

async fn check_structures(tx: &mut Transaction<'_, Postgres>) -> Result<(), ControlError> {
    sqlx_core::query::query("SET LOCAL search_path TO pg_temp,pg_catalog,public")
        .execute(&mut **tx)
        .await
        .map_err(|_| ControlError::SchemaRejected)?;
    for table in TABLES {
        // Only producer-owned closed producer DDL is transformed. No caller text or identifier enters SQL.
        let statement = table.create_statement(Dialect::Postgres).replacen(
            "CREATE TABLE IF NOT EXISTS",
            "CREATE TEMP TABLE",
            1,
        ) + " ON COMMIT DROP";
        sqlx_core::query::query(AssertSqlSafe(statement))
            .execute(&mut **tx)
            .await
            .map_err(|_| ControlError::SchemaRejected)?;
    }
    let namespace: String = sqlx_core::query_scalar::query_scalar("SELECT nspname::text FROM pg_catalog.pg_namespace WHERE oid=pg_catalog.pg_my_temp_schema()")
        .fetch_one(&mut **tx).await.map_err(|_| ControlError::SchemaRejected)?;
    for table in TABLES {
        let actual = shape(tx, "public", *table).await?;
        let expected = shape(tx, &namespace, *table).await?;
        if actual != expected
            || actual["regular"] != true
            || actual["private_owner"] != true
            || actual["rls"] != false
            || actual["force_rls"] != false
            || actual["inherits"] != false
            || actual["triggers_ok"] != true
            || actual["rules_ok"] != true
        {
            return Err(ControlError::SchemaRejected);
        }
        let durable: bool = sqlx_core::query_scalar::query_scalar("SELECT c.relpersistence='p' FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1")
            .bind(table.name()).fetch_one(&mut **tx).await.map_err(|_| ControlError::SchemaRejected)?;
        if !durable {
            return Err(ControlError::SchemaRejected);
        }
    }
    sqlx_core::query::query("SET LOCAL search_path TO pg_catalog,public")
        .execute(&mut **tx)
        .await
        .map_err(|_| ControlError::SchemaRejected)?;
    Ok(())
}

pub(crate) async fn initialize(tx: &mut Transaction<'_, Postgres>) -> Result<(), ControlError> {
    sqlx_core::query::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
        .bind(STARTUP_LOCK)
        .execute(&mut **tx)
        .await
        .map_err(|_| ControlError::Storage)?;
    let existing = inventory(tx).await?;
    let fresh = existing.is_empty();
    if !fresh {
        let mut expected: Vec<_> = TABLES.iter().map(|v| v.name().to_owned()).collect();
        expected.sort();
        if existing != expected {
            return Err(ControlError::SchemaRejected);
        }
        let (format, epoch): (String, i64) =
            sqlx_core::query_as::query_as("SELECT format,epoch FROM public.schema_meta WHERE id=1")
                .fetch_one(&mut **tx)
                .await
                .map_err(|_| ControlError::SchemaRejected)?;
        SchemaVersion::validate(&format, epoch).map_err(|_| ControlError::SchemaRejected)?;
    } else {
        for table in TABLES {
            sqlx_core::query::query(AssertSqlSafe(
                table.create_statement(Dialect::Postgres).replacen(
                    "CREATE TABLE IF NOT EXISTS ",
                    "CREATE TABLE IF NOT EXISTS public.",
                    1,
                ),
            ))
            .execute(&mut **tx)
            .await
            .map_err(|_| ControlError::Storage)?;
        }
    }
    check_structures(tx).await?;
    let seeds =
        InitialSeeds::new(TimestampMicros::new(now_micros()?).map_err(|_| ControlError::Clock)?);
    let now = seeds.timestamp().as_i64();
    for role in seeds.roles() {
        sqlx_core::query::query(
            "INSERT INTO public.roles(name,created_at) VALUES($1,$2) ON CONFLICT(name) DO NOTHING",
        )
        .bind(role.name())
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|_| ControlError::Storage)?;
        sqlx_core::query::query("DELETE FROM public.role_permissions WHERE role=$1")
            .bind(role.name())
            .execute(&mut **tx)
            .await
            .map_err(|_| ControlError::Storage)?;
        for action in role.actions() {
            sqlx_core::query::query(
                "INSERT INTO public.role_permissions(role,action) VALUES($1,$2)",
            )
            .bind(role.name())
            .bind(action.as_str())
            .execute(&mut **tx)
            .await
            .map_err(|_| ControlError::Storage)?;
        }
    }
    sqlx_core::query::query("INSERT INTO public.resource_acl_state(id,revision,updated_at) VALUES(1,$1,$2) ON CONFLICT(id) DO NOTHING")
        .bind(seeds.acl_revision()).bind(now).execute(&mut **tx).await.map_err(|_| ControlError::Storage)?;
    if fresh {
        sqlx_core::query::query("INSERT INTO public.schema_meta(id,format,epoch) VALUES(1,$1,$2)")
            .bind(SchemaVersion::FORMAT)
            .bind(SchemaVersion::EPOCH)
            .execute(&mut **tx)
            .await
            .map_err(|_| ControlError::Storage)?;
    }
    Ok(())
}

/// One isolation choice for bootstrap, save and consume; never inherit the role default.
pub(crate) async fn transaction(
    connection: &mut PgConnection,
) -> Result<Transaction<'_, Postgres>, ControlError> {
    use sqlx_core::connection::Connection;
    connection
        .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(|_| ControlError::Storage)
}
