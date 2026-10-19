use super::{
    MySqlControlError, RequiredCapability, Result, UnprovenReason,
    config::identifier,
    executor::{Lease, native_error},
};
use broker_store::schema::TABLES;
use futures_util::TryStreamExt;
use sqlparser::{
    dialect::{Dialect, MySqlDialect},
    tokenizer::{Token, Tokenizer, Whitespace},
};
use sqlx_core::sql_str::AssertSqlSafe;

const SELECT: u8 = 1;
const TRIGGER: u8 = 2;
const CREATE: u8 = 4;
const REFERENCES: u8 = 8;
const PROCESS: u8 = 16;
#[derive(Clone, Copy)]
pub(crate) enum Operation {
    Startup,
    Save,
    Consume,
    CreateSession,
    ReadSession,
    RevokeSession,
    ReadLocalIdentity,
}
struct Grant {
    database: String,
    table: Option<String>,
    privileges: u8,
}
pub(crate) struct Grants {
    entries: Vec<Grant>,
    partial_revokes: bool,
    process: bool,
}
impl Grants {
    pub(crate) async fn read(lease: &mut Lease) -> Result<Self> {
        const SQL: &str = "SHOW GRANTS FOR CURRENT_USER";
        lease.work.statement(SQL)?;
        let mut stream = sqlx_core::query::query(SQL).fetch(&mut lease.connection);
        let mut entries = Vec::new();
        let mut principal = None;
        let mut process = false;
        let mut rows = 0usize;
        let mut bytes = 0usize;
        while let Some(row) = stream.try_next().await.map_err(|_| unproven())? {
            rows = rows.checked_add(1).ok_or_else(unproven)?;
            if rows > lease.work.limits.grant_rows.get() {
                return Err(unproven());
            }
            let line = lease
                .work
                .text(&row, 0, lease.work.limits.grant_bytes.get())?
                .ok_or_else(unproven)?;
            bytes = bytes.checked_add(line.len()).ok_or_else(unproven)?;
            if bytes > lease.work.limits.grant_bytes.get() {
                return Err(unproven());
            }
            let parsed = decode(&line, lease.work.limits.grant_tokens.get())?;
            if format!("{}@{}", parsed.principal.0, parsed.principal.1)
                != lease.observation.principal
            {
                return Err(unproven());
            }
            if principal.as_ref().is_some_and(|p| p != &parsed.principal) {
                return Err(unproven());
            }
            principal = Some(parsed.principal);
            process |= parsed.process;
            if let Some(grant) = parsed.grant {
                entries.push(grant);
            }
        }
        if rows == 0 {
            return Err(unproven());
        }
        Ok(Self {
            entries,
            partial_revokes: lease.observation.partial_revokes,
            process,
        })
    }
    fn covers(&self, database: &str, table: Option<&str>, privilege: u8) -> bool {
        self.entries.iter().any(|grant| {
            if grant.privileges & privilege == 0 {
                return false;
            }
            match &grant.table {
                Some(actual) => grant.database == database && table == Some(actual.as_str()),
                None => {
                    literal_database(&grant.database, self.partial_revokes).as_deref()
                        == Some(database)
                }
            }
        })
    }
    pub(crate) fn process(&self) -> Result<()> {
        if self.process {
            Ok(())
        } else {
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        }
    }
    pub(crate) fn relations(&self, database: &str) -> Result<()> {
        if self.covers(database, None, SELECT) {
            Ok(())
        } else {
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        }
    }
    pub(crate) fn triggers(&self, database: &str) -> Result<()> {
        for table in TABLES {
            if !self.covers(database, Some(table.name()), TRIGGER) {
                return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
            }
        }
        Ok(())
    }
    pub(crate) fn creation(&self, database: &str) -> Result<()> {
        for table in TABLES {
            if !self.covers(database, Some(table.name()), CREATE) {
                return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
            }
            for key in table.mysql_shape().foreign_keys() {
                if !self.covers(database, Some(key.target_table()), REFERENCES) {
                    return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
                }
            }
        }
        Ok(())
    }
}
pub(crate) async fn events_absent(lease: &mut Lease) -> Result<()> {
    let sql = format!(
        "SHOW EVENTS FROM {}",
        identifier(
            &lease.observation.database,
            lease.work.limits.statement_bytes.get()
        )?
    );
    lease.work.statement(&sql)?;
    let mut stream = sqlx_core::query::query(AssertSqlSafe(sql)).fetch(&mut lease.connection);
    if stream
        .try_next()
        .await
        .map_err(|error| native_error(&error, RequiredCapability::Event))?
        .is_some()
    {
        return Err(MySqlControlError::SchemaRejected(
            super::SchemaReason::Event,
        ));
    }
    Ok(())
}
pub(crate) async fn explain(lease: &mut Lease, operation: Operation) -> Result<()> {
    let database = identifier(
        &lease.observation.database,
        lease.work.limits.statement_bytes.get(),
    )?;
    let read_probe;
    let queries: Vec<(&str, RequiredCapability)> = match operation {
        Operation::Startup => vec![
            (
                "SELECT name,created_at FROM roles WHERE FALSE FOR UPDATE",
                RequiredCapability::Select,
            ),
            (
                "INSERT INTO roles(name,created_at) VALUES('capability-only',0)",
                RequiredCapability::Insert,
            ),
            (
                "SELECT role,action FROM role_permissions WHERE FALSE",
                RequiredCapability::Select,
            ),
            (
                "DELETE FROM role_permissions WHERE FALSE",
                RequiredCapability::Delete,
            ),
            (
                "INSERT INTO role_permissions(role,action) VALUES('capability-only','capability-only')",
                RequiredCapability::Insert,
            ),
            (
                "SELECT id,revision,updated_at FROM resource_acl_state WHERE FALSE FOR UPDATE",
                RequiredCapability::Select,
            ),
            (
                "INSERT INTO resource_acl_state(id,revision,updated_at) VALUES(1,1,0)",
                RequiredCapability::Insert,
            ),
            (
                "SELECT id,format,epoch FROM schema_meta WHERE FALSE",
                RequiredCapability::Select,
            ),
            (
                "INSERT INTO schema_meta(id,format,epoch) VALUES(1,'capability-only',1)",
                RequiredCapability::Insert,
            ),
        ],
        Operation::CreateSession => vec![
            (
                "INSERT INTO admin_sessions(token_hash,subject,name,email,csrf_token,expires_at,created_at) VALUES('capability-only','s','','','c',1,0)",
                RequiredCapability::Insert,
            ),
            (
                "INSERT INTO admin_session_principals(token_hash,issuer,username,organization,teams_json,local_user_revision) VALUES('capability-only','i','','','[]',0)",
                RequiredCapability::Insert,
            ),
            (
                "INSERT INTO admin_session_claim_roles(token_hash,claim_selector,roles_json) VALUES('capability-only','roles','[\"metadata\"]')",
                RequiredCapability::Insert,
            ),
        ],
        Operation::ReadSession => {
            read_probe = session_select(&database, true);
            vec![
                (&read_probe, RequiredCapability::Select),
                (
                    "DELETE FROM admin_sessions WHERE token_hash='capability-only' AND FALSE",
                    RequiredCapability::Delete,
                ),
            ]
        }
        Operation::ReadLocalIdentity => {
            read_probe = identity_select(&database, true);
            vec![(&read_probe, RequiredCapability::Select)]
        }
        Operation::RevokeSession => vec![(
            "DELETE FROM admin_sessions WHERE token_hash='capability-only' AND FALSE",
            RequiredCapability::Delete,
        )],
        Operation::Save => vec![(
            "INSERT INTO oidc_flows(state_hash,browser_binding_hash,nonce,pkce_verifier,purpose,continuation_json,expires_at,created_at) VALUES('capability-only','capability-only','n','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','admin','{}',1,0)",
            RequiredCapability::Insert,
        )],
        Operation::Consume => vec![
            (
                "SELECT nonce,pkce_verifier,purpose,continuation_json,expires_at,created_at FROM oidc_flows WHERE state_hash='capability-only' AND browser_binding_hash='capability-only' AND FALSE FOR UPDATE",
                RequiredCapability::Select,
            ),
            (
                "DELETE FROM oidc_flows WHERE state_hash='capability-only' AND browser_binding_hash='capability-only' AND FALSE",
                RequiredCapability::Delete,
            ),
        ],
    };
    for (query, required) in queries {
        // Only these internal table names occur in the closed operation templates.
        let mut qualified = query.to_owned();
        for name in [
            "admin_session_principals",
            "admin_session_claim_roles",
            "admin_sessions",
            "role_permissions",
            "resource_acl_state",
            "schema_meta",
            "oidc_flows",
            "roles",
        ] {
            for keyword in ["FROM ", "INTO ", "JOIN "] {
                qualified = qualified.replace(
                    &format!("{keyword}{name}"),
                    &format!("{keyword}{database}.`{name}`"),
                );
            }
        }
        let sql = format!("EXPLAIN FORMAT=TRADITIONAL {qualified}");
        lease.work.statement(&sql)?;
        let mut stream = sqlx_core::query::query(AssertSqlSafe(sql)).fetch(&mut lease.connection);
        let mut count = 0usize;
        while let Some(row) =
            stream
                .try_next()
                .await
                .map_err(|error| match native_error(&error, required) {
                    MySqlControlError::Denied(cap) => MySqlControlError::Denied(cap),
                    _ => MySqlControlError::Unproven(UnprovenReason::Visibility),
                })?
        {
            count += 1;
            if count > lease.work.limits.rows_per_category.get() {
                return Err(unproven());
            }
            for index in 0..sqlx_core::row::Row::len(&row) {
                // Public Decode<&[u8]> borrows the received native field, including
                // binary numeric fields. No protocol parsing or type-size estimate.
                let raw = sqlx_core::row::Row::try_get_unchecked::<Option<&[u8]>, _>(&row, index)
                    .map_err(|_| unproven())?;
                if let Some(raw) = raw {
                    if raw.len() > lease.work.limits.cell_bytes.get() {
                        return Err(unproven());
                    }
                    lease.work.bytes(raw.len())?;
                }
            }
        }
        if count == 0 {
            return Err(unproven());
        }
    }
    Ok(())
}
// The capability probe and the real reader share the closed projection. Probe
// literals are never payload policy: FALSE ensures no rows or writes are read.
pub(super) fn session_select(database: &str, probe: bool) -> String {
    let sql = format!(
        "SELECT CASE WHEN OCTET_LENGTH(s.subject)<=? THEN s.subject END AS subject,CASE WHEN OCTET_LENGTH(s.name)<=? THEN s.name END AS name,CASE WHEN OCTET_LENGTH(s.email)<=? THEN s.email END AS email,CASE WHEN OCTET_LENGTH(s.csrf_token)<=? THEN s.csrf_token END AS csrf,s.created_at,s.expires_at,CAST(p.token_hash IS NOT NULL AS SIGNED) AS principal_present,CASE WHEN OCTET_LENGTH(p.issuer)<=? THEN p.issuer END AS issuer,CASE WHEN OCTET_LENGTH(p.username)<=? THEN p.username END AS username,CASE WHEN OCTET_LENGTH(p.organization)<=? THEN p.organization END AS organization,CASE WHEN OCTET_LENGTH(p.teams_json)<=? THEN p.teams_json END AS teams,p.local_user_revision,CAST(c.token_hash IS NOT NULL AS SIGNED) AS claims_present,CASE WHEN OCTET_LENGTH(c.claim_selector)<=? THEN c.claim_selector END AS selector,CASE WHEN OCTET_LENGTH(c.roles_json)<=? THEN c.roles_json END AS roles FROM {database}.`admin_sessions` s LEFT JOIN {database}.`admin_session_principals` p ON p.token_hash=s.token_hash LEFT JOIN {database}.`admin_session_claim_roles` c ON c.token_hash=s.token_hash WHERE s.token_hash=? FOR UPDATE OF s"
    );
    if probe {
        sql.replace(
            "WHERE s.token_hash=?",
            "WHERE s.token_hash='capability-only' AND FALSE",
        )
        .replace('?', "65535")
    } else {
        sql
    }
}
struct Parsed {
    principal: (String, String),
    grant: Option<Grant>,
    process: bool,
}
// Tokenization only: delegate every lexical switch used by sqlparser 0.63
// to MySQL, preserving its identity, except executable comment expansion.
// Keeping comments as tokens lets the closed grammar reject them, while
// comment-looking text inside quoted accounts/identifiers stays literal.
#[derive(Debug)]
struct MysqlMetadataDialect;
macro_rules! mysql_lexical_switches {
    ($($name:ident),+ $(,)?) => {
        $(fn $name(&self) -> bool { MySqlDialect {}.$name() })+
    };
}
impl Dialect for MysqlMetadataDialect {
    fn dialect(&self) -> std::any::TypeId {
        std::any::TypeId::of::<MySqlDialect>()
    }
    fn is_identifier_start(&self, ch: char) -> bool {
        MySqlDialect {}.is_identifier_start(ch)
    }
    fn is_identifier_part(&self, ch: char) -> bool {
        MySqlDialect {}.is_identifier_part(ch)
    }
    fn is_delimited_identifier_start(&self, ch: char) -> bool {
        MySqlDialect {}.is_delimited_identifier_start(ch)
    }
    fn is_custom_operator_part(&self, ch: char) -> bool {
        MySqlDialect {}.is_custom_operator_part(ch)
    }
    fn supports_multiline_comment_hints(&self) -> bool {
        false
    }
    mysql_lexical_switches!(
        ignores_wildcard_escapes,
        requires_single_line_comment_whitespace,
        supports_dollar_as_money_prefix,
        supports_dollar_placeholder,
        supports_geometric_types,
        supports_nested_comments,
        supports_numeric_literal_underscores,
        supports_numeric_prefix,
        supports_pipe_operator,
        supports_quote_delimited_string,
        supports_string_escape_constant,
        supports_string_literal_backslash_escape,
        supports_triple_quoted_string,
        supports_unicode_string_literal,
    );
}
pub(crate) fn tokens(line: &str, maximum: usize) -> Result<Vec<Token>> {
    let dialect = MysqlMetadataDialect;
    let raw = Tokenizer::new(&dialect, line)
        .with_unescape(false)
        .tokenize()
        .map_err(|_| unproven())?;
    if raw.len() > maximum {
        return Err(unproven());
    }
    let mut output = Vec::new();
    for token in raw {
        match token {
            Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline) => {}
            Token::Whitespace(_) | Token::SemiColon => return Err(unproven()),
            token => output.push(token),
        }
    }
    Ok(output)
}
struct Cursor {
    tokens: Vec<Token>,
    at: usize,
}
const GLOBAL_SCOPE: u8 = 1;
const DATABASE_SCOPE: u8 = 2;
const TABLE_SCOPE: u8 = 4;
const ROUTINE_SCOPE: u8 = 8;
const OBJECT_SCOPES: u8 = GLOBAL_SCOPE | DATABASE_SCOPE | TABLE_SCOPE;
struct Privileges {
    positive: u8,
    scopes: u8,
}
impl Cursor {
    fn word(&mut self, value: &str) -> bool {
        if self.tokens.get(self.at).is_some_and(|token| matches!(token,Token::Word(word) if word.quote_style.is_none() && word.value == value)) { self.at += 1; true } else { false }
    }
    fn symbol(&mut self, value: Token) -> bool {
        if self.tokens.get(self.at) == Some(&value) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn ident(&mut self) -> Result<String> {
        let value = match self.tokens.get(self.at) {
            Some(Token::Word(word)) if word.quote_style == Some('`') => {
                word.value.replace("``", "`")
            }
            _ => return Err(unproven()),
        };
        self.at += 1;
        Ok(value)
    }
    fn account(&mut self) -> Result<(String, String)> {
        let name = self.ident()?;
        if !self.symbol(Token::AtSign) {
            return Err(unproven());
        }
        Ok((name, self.ident()?))
    }
    fn finish(&mut self, role: bool) -> Result<()> {
        if self.word("WITH")
            && (!self.word(if role { "ADMIN" } else { "GRANT" }) || !self.word("OPTION"))
        {
            return Err(unproven());
        }
        if self.at == self.tokens.len() {
            Ok(())
        } else {
            Err(unproven())
        }
    }
    fn privileges(&mut self) -> Result<Privileges> {
        if self.word("ALL") {
            if !self.word("PRIVILEGES") {
                return Err(unproven());
            }
            return Ok(Privileges {
                positive: SELECT | TRIGGER | CREATE | REFERENCES | PROCESS,
                scopes: OBJECT_SCOPES | ROUTINE_SCOPE,
            });
        }
        if self.word("USAGE") {
            return Ok(Privileges {
                positive: 0,
                scopes: OBJECT_SCOPES | ROUTINE_SCOPE,
            });
        }
        let mut output = Privileges {
            positive: 0,
            scopes: OBJECT_SCOPES | ROUTINE_SCOPE,
        };
        loop {
            let (bit, scopes, column) = if self.word("SELECT") {
                (SELECT, OBJECT_SCOPES, true)
            } else if self.word("PROCESS") {
                (PROCESS, GLOBAL_SCOPE, false)
            } else if self.word("TRIGGER") {
                (TRIGGER, OBJECT_SCOPES, false)
            } else if self.word("REFERENCES") {
                (REFERENCES, OBJECT_SCOPES, true)
            } else if self.word("CREATE") {
                if self.word("VIEW") {
                    (0, OBJECT_SCOPES, false)
                } else if self.word("ROUTINE") {
                    (0, GLOBAL_SCOPE | DATABASE_SCOPE, false)
                } else if self.word("TEMPORARY") {
                    if !self.word("TABLES") {
                        return Err(unproven());
                    }
                    (0, GLOBAL_SCOPE | DATABASE_SCOPE, false)
                } else {
                    (CREATE, OBJECT_SCOPES, false)
                }
            } else if self.word("SHOW") {
                if !self.word("VIEW") {
                    return Err(unproven());
                }
                (0, OBJECT_SCOPES, false)
            } else if self.word("LOCK") {
                if !self.word("TABLES") {
                    return Err(unproven());
                }
                (0, GLOBAL_SCOPE | DATABASE_SCOPE, false)
            } else if self.word("ALTER") {
                if self.word("ROUTINE") {
                    (0, GLOBAL_SCOPE | DATABASE_SCOPE | ROUTINE_SCOPE, false)
                } else {
                    (0, OBJECT_SCOPES, false)
                }
            } else if ["INSERT", "UPDATE"].iter().any(|name| self.word(name)) {
                (0, OBJECT_SCOPES, true)
            } else if ["DELETE", "DROP", "INDEX"]
                .iter()
                .any(|name| self.word(name))
            {
                (0, OBJECT_SCOPES, false)
            } else if self.word("EXECUTE") {
                (0, GLOBAL_SCOPE | DATABASE_SCOPE | ROUTINE_SCOPE, false)
            } else if self.word("EVENT") {
                (0, GLOBAL_SCOPE | DATABASE_SCOPE, false)
            } else {
                return Err(unproven());
            };
            output.scopes &= scopes;
            if self.symbol(Token::LParen) {
                if !column {
                    return Err(unproven());
                }
                output.scopes &= TABLE_SCOPE;
                self.ident()?;
                while self.symbol(Token::Comma) {
                    self.ident()?;
                }
                if !self.symbol(Token::RParen) {
                    return Err(unproven());
                }
            } else {
                output.positive |= bit;
            }
            if !self.symbol(Token::Comma) {
                break;
            }
        }
        Ok(output)
    }
}
fn decode(line: &str, maximum: usize) -> Result<Parsed> {
    let mut cursor = Cursor {
        tokens: tokens(line, maximum)?,
        at: 0,
    };
    let revoke = cursor.word("REVOKE");
    if !revoke && !cursor.word("GRANT") {
        return Err(unproven());
    }
    if cursor.word("PROXY") {
        if revoke || !cursor.word("ON") {
            return Err(unproven());
        }
        cursor.account()?;
        if !cursor.word("TO") {
            return Err(unproven());
        }
        let principal = cursor.account()?;
        cursor.finish(false)?;
        return Ok(Parsed {
            principal,
            grant: None,
            process: false,
        });
    }
    // Role grants are observations, not positive object privileges.
    if matches!(cursor.tokens.get(cursor.at),Some(Token::Word(word)) if word.quote_style.is_some())
    {
        cursor.account()?;
        while cursor.symbol(Token::Comma) {
            cursor.account()?;
        }
        if !cursor.word(if revoke { "FROM" } else { "TO" }) {
            return Err(unproven());
        }
        let principal = cursor.account()?;
        cursor.finish(true)?;
        return Ok(Parsed {
            principal,
            grant: None,
            process: false,
        });
    }
    let privileges = cursor.privileges()?;
    if !cursor.word("ON") {
        return Err(unproven());
    }
    let routine = cursor.word("PROCEDURE") || cursor.word("FUNCTION");
    let global = cursor.symbol(Token::Mul);
    let database = if global {
        String::new()
    } else {
        cursor.ident()?
    };
    if !cursor.symbol(Token::Period) {
        return Err(unproven());
    }
    let table = if cursor.symbol(Token::Mul) {
        None
    } else {
        Some(cursor.ident()?)
    };
    if global && table.is_some() {
        return Err(unproven());
    }
    if !cursor.word(if revoke { "FROM" } else { "TO" }) {
        return Err(unproven());
    }
    let principal = cursor.account()?;
    cursor.finish(false)?;
    if routine && (global || table.is_none()) {
        return Err(unproven());
    }
    let scope = if global {
        GLOBAL_SCOPE
    } else if routine {
        ROUTINE_SCOPE
    } else if table.is_some() {
        TABLE_SCOPE
    } else {
        DATABASE_SCOPE
    };
    if privileges.scopes & scope == 0 {
        return Err(unproven());
    }
    let process = global && !revoke && !routine && privileges.positive & PROCESS != 0;
    let grant = if global || revoke || routine {
        None
    } else {
        Some(Grant {
            database,
            table,
            privileges: privileges.positive & (SELECT | TRIGGER | CREATE | REFERENCES),
        })
    };
    Ok(Parsed {
        principal,
        grant,
        process,
    })
}
fn literal_database(pattern: &str, partial_revokes: bool) -> Option<String> {
    if partial_revokes {
        return Some(pattern.to_owned());
    }
    let mut chars = pattern.chars();
    let mut literal = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '%' | '_' => return None,
            '\\' => literal.push(chars.next()?),
            ch => literal.push(ch),
        }
    }
    Some(literal)
}
fn unproven() -> MySqlControlError {
    MySqlControlError::Unproven(UnprovenReason::GrantSyntax)
}

/// One consistent nonlocking read; the proof probes exactly its selected columns.
pub(crate) fn identity_select(database: &str, probe: bool) -> String {
    let (username_cap, subject_cap, role_cap, subject, username, limit, predicate) = if probe {
        (
            "128",
            "512",
            "128",
            "'local|capability-only'",
            "'capability-only'",
            "1",
            " AND FALSE",
        )
    } else {
        ("?", "?", "?", "?", "?", "?", "")
    };
    format!(
        "SELECT CASE WHEN OCTET_LENGTH(u.username)<={username_cap} THEN u.username ELSE NULL END,CASE WHEN OCTET_LENGTH(u.subject)<={subject_cap} THEN u.subject ELSE NULL END,CASE WHEN OCTET_LENGTH(u.identity_kind)<=16 THEN u.identity_kind ELSE NULL END,CAST(u.enabled AS SIGNED),CAST(u.revision AS SIGNED),CASE WHEN OCTET_LENGTH(a.role)<={role_cap} THEN a.role ELSE NULL END,CASE WHEN OCTET_LENGTH(p.action)<=128 THEN p.action ELSE NULL END,CAST(a.role IS NOT NULL AS SIGNED),CAST(p.action IS NOT NULL AS SIGNED) FROM {database}.`local_users` u LEFT JOIN (SELECT role FROM {database}.`role_assignments` WHERE subject={subject} UNION SELECT 'user' AS role) a ON TRUE LEFT JOIN {database}.`roles` r ON r.name=a.role LEFT JOIN {database}.`role_permissions` p ON p.role=r.name WHERE u.username={username}{predicate} ORDER BY a.role,p.action LIMIT {limit}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const MYSQL_VISIBILITY_EXPECTED: bool = false;
    #[test]
    fn wildcard_grant_cannot_prove_literal_database() {
        let parsed = decode(
            "GRANT SELECT, TRIGGER ON `broker_%`.* TO `u@x`@`localhost`",
            128,
        )
        .unwrap();
        assert_eq!(parsed.principal, ("u@x".into(), "localhost".into()));
        let grants = Grants {
            entries: vec![parsed.grant.unwrap()],
            partial_revokes: false,
            process: false,
        };
        assert_eq!(
            grants.covers("broker_demo", None, SELECT),
            MYSQL_VISIBILITY_EXPECTED,
            "MYSQL_VISIBILITY_ORACLE"
        );
        assert_eq!(
            literal_database(r"broker\_demo", false),
            Some("broker_demo".into())
        );
        assert_eq!(
            literal_database(r"broker\_demo", true),
            Some(r"broker\_demo".into())
        );
    }
    #[test]
    fn native_table_scope_columns_and_quoted_account_are_distinct() {
        let parsed = decode("GRANT SELECT (`a`), SELECT, REFERENCES (`a`), TRIGGER ON `db_%`.`t` TO `u``@x`@`h` WITH GRANT OPTION",128).unwrap();
        assert_eq!(parsed.principal.0, "u`@x");
        let grants = Grants {
            entries: vec![parsed.grant.unwrap()],
            partial_revokes: false,
            process: false,
        };
        assert!(grants.covers("db_%", Some("t"), SELECT));
        assert!(!grants.covers("db_%", Some("t"), REFERENCES));
        assert!(grants.covers("db_%", Some("t"), TRIGGER));
        assert!(!grants.covers("db_%", None, SELECT));
    }
    #[test]
    fn all_scope_and_nonpositive_role_global_revoke_are_closed() {
        let all = decode("GRANT ALL PRIVILEGES ON `db`.* TO `u`@`h`", 128).unwrap();
        assert_eq!(
            all.grant.unwrap().privileges,
            SELECT | TRIGGER | CREATE | REFERENCES
        );
        for line in [
            "GRANT USAGE ON *.* TO `u`@`h`",
            "GRANT `role`@`%` TO `u`@`h`",
            "REVOKE SELECT ON `db`.* FROM `u`@`h`",
        ] {
            assert!(decode(line, 128).unwrap().grant.is_none());
        }
        for line in [
            "GRANT SELECT ON `db`.* TO `u`@`h`;",
            "GRANT SELECT ON `db`.* TO `u`@`h` /* ignored */",
            "GRANT SELECT ON `db`.* TO `u`@`h` /*! WITH GRANT OPTION */",
            "GRANT SELECT ON `db`.* TO `u`@`h` /*!80000 WITH GRANT OPTION */",
            "GRANT SELECT ON `db`.* TO `u`@`h` /*! */",
            "GRANT SELECT ON `db`.* TO `u`@`h` /*!80000 */",
            "GRANT made_up ON `db`.* TO `u`@`h`",
            "GRANT CREATE TEMPORARY TABLES, TRIGGER ON `db`.`t` TO `u`@`h`",
            "GRANT EVENT, SELECT ON `db`.`t` TO `u`@`h`",
            "GRANT LOCK TABLES, REFERENCES ON `db`.`t` TO `u`@`h`",
            "GRANT CREATE ROUTINE, TRIGGER ON `db`.`t` TO `u`@`h`",
            "GRANT EXECUTE, SELECT ON `db`.`t` TO `u`@`h`",
            "GRANT TRIGGER (`a`), SELECT ON `db`.`t` TO `u`@`h`",
            "GRANT SELECT (`a`), TRIGGER ON `db`.* TO `u`@`h`",
            "GRANT TRIGGER ON PROCEDURE `db`.`routine` TO `u`@`h`",
            "GRANT CREATE ROUTINE ON PROCEDURE `db`.`routine` TO `u`@`h`",
        ] {
            assert!(decode(line, 128).is_err());
        }
        let quoted = decode(
            "GRANT SELECT ON `db/*!80000 */`.* TO `u/*! */`@`h/* */`",
            128,
        )
        .unwrap();
        assert_eq!(quoted.principal, ("u/*! */".into(), "h/* */".into()));
        assert_eq!(quoted.grant.unwrap().database, "db/*!80000 */");
        assert!(tokens("row_format=DYNAMIC /*! checksum=1 */", 128).is_err());
        assert!(tokens("row_format=DYNAMIC /*!80000 checksum=1 */", 128).is_err());
    }
    #[test]
    fn process_proof_requires_global_scope_without_object_elevation() {
        for line in [
            "GRANT PROCESS ON *.* TO `u`@`h`",
            "GRANT ALL PRIVILEGES ON *.* TO `u`@`h`",
            "GRANT SELECT, PROCESS ON *.* TO `u`@`h` WITH GRANT OPTION",
        ] {
            let parsed = decode(line, 256).unwrap();
            assert!(parsed.process);
            assert!(parsed.grant.is_none());
            let grants = Grants {
                entries: vec![],
                partial_revokes: false,
                process: parsed.process,
            };
            assert_eq!(grants.process(), Ok(()));
            assert!(!grants.covers("broker", None, SELECT));
        }
        for line in [
            "GRANT ALL PRIVILEGES ON `broker`.* TO `u`@`h`",
            "GRANT ALL PRIVILEGES ON `broker`.`roles` TO `u`@`h`",
            "REVOKE PROCESS ON *.* FROM `u`@`h`",
            "GRANT `role`@`h` TO `u`@`h`",
        ] {
            let parsed = decode(line, 256).unwrap();
            assert!(!parsed.process);
            if let Some(grant) = parsed.grant {
                assert_eq!(grant.privileges, SELECT | TRIGGER | CREATE | REFERENCES);
            }
        }
        for line in [
            "GRANT PROCESS ON `broker`.* TO `u`@`h`",
            "GRANT PROCESS ON `broker`.`roles` TO `u`@`h`",
            "GRANT PROCESS(`name`) ON *.* TO `u`@`h`",
            "GRANT PROCESS ON PROCEDURE `broker`.`p` TO `u`@`h`",
            "GRANT PROCESS, SELECT ON `broker`.* TO `u`@`h`",
        ] {
            assert!(decode(line, 256).is_err());
        }
        let grants = Grants {
            entries: vec![],
            partial_revokes: false,
            process: false,
        };
        assert_eq!(
            grants.process(),
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        );
    }
}
