//! Provider relations, stable primary projection and explicit mutation admission.
use crate::database::DB;
use crate::entity::auth_providers::AuthProvider;
use crate::entity::identity_link_audit::{IdentityLinkAudit, LinkChange};
use crate::entity::users::User;
use hiqlite::macros::params;
use rauthy_api_types::auth_providers::{ProviderLinkAuditState, ProviderLinkResponse};
use rauthy_common::is_hiqlite;
use rauthy_common::utils::new_store_id;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};

/// Inserts one link. `$1` provider, `$2` federation uid, `$3` user, `$4` created.
pub(crate) static SQL_INSERT: &str = r#"
INSERT INTO identity_links (provider_id, federation_uid, user_id, created)
VALUES ($1, $2, $3, $4)"#;

/// Repairs the single provider pair on `users` when it no longer names one of the user's links:
/// it then names the oldest remaining link, or nothing when none is left. A pair that still
/// names a link is kept, so the primary link only moves when it is removed. `$1` user.
pub(crate) static SQL_PRIMARY: &str = r#"
UPDATE users SET
auth_provider_id = (
    SELECT provider_id FROM identity_links WHERE user_id = $1
    ORDER BY created ASC, provider_id ASC LIMIT 1
),
federation_uid = (
    SELECT federation_uid FROM identity_links WHERE user_id = $1
    ORDER BY created ASC, provider_id ASC LIMIT 1
)
WHERE id = $1
AND NOT EXISTS (
    SELECT 1 FROM identity_links l
    WHERE l.user_id = $1
    AND l.provider_id = users.auth_provider_id
    AND l.federation_uid = users.federation_uid
)"#;

/// One upstream provider identity linked to one user.
///
/// A provider identity (`provider_id`, `federation_uid`) names at most one user, and a user
/// holds at most one identity per provider. Linking never changes the user's id, and a link is
/// only ever made for the user a signed-in person asked for, never by matching an email.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, FromPgRow)]
pub struct IdentityLink {
    pub provider_id: String,
    pub federation_uid: String,
    pub user_id: String,
    pub created: i64,
}

impl IdentityLink {
    pub async fn find(
        provider_id: &str,
        federation_uid: &str,
    ) -> Result<Option<Self>, ErrorResponse> {
        let sql = "SELECT * FROM identity_links WHERE provider_id = $1 AND federation_uid = $2";
        let res = if is_hiqlite() {
            DB::hql()
                .query_as_optional(sql, params!(provider_id, federation_uid))
                .await?
        } else {
            DB::pg_query_opt(sql, &[&provider_id, &federation_uid]).await?
        };
        Ok(res)
    }

    /// Every link of `user_id`, oldest first.
    pub async fn find_by_user(user_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let sql = r#"
SELECT * FROM identity_links WHERE user_id = $1
ORDER BY created ASC, provider_id ASC"#;
        let res = if is_hiqlite() {
            DB::hql().query_as(sql, params!(user_id)).await?
        } else {
            DB::pg_query(sql, &[&user_id], 2).await?
        };
        Ok(res)
    }

    pub async fn find_by_provider(provider_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let sql = "SELECT * FROM identity_links WHERE provider_id = $1";
        let res = if is_hiqlite() {
            DB::hql().query_as(sql, params!(provider_id)).await?
        } else {
            DB::pg_query(sql, &[&provider_id], 0).await?
        };
        Ok(res)
    }

    /// Refuses a link of (`provider_id`, `federation_uid`) to `user_id` if that identity is
    /// linked already, or the user already holds an identity of this provider.
    pub async fn check_free(
        user_id: &str,
        provider_id: &str,
        federation_uid: &str,
    ) -> Result<(), ErrorResponse> {
        if let Some(existing) = Self::find(provider_id, federation_uid).await? {
            return Err(if existing.user_id == user_id {
                ErrorResponse::new(
                    ErrorResponseType::BadRequest,
                    "identity_link_exists: this provider identity is already linked to you",
                )
            } else {
                refused_taken()
            });
        }
        Self::check_provider_free(user_id, provider_id).await
    }

    /// Refuses a second identity of `provider_id` for `user_id`.
    pub async fn check_provider_free(
        user_id: &str,
        provider_id: &str,
    ) -> Result<(), ErrorResponse> {
        if Self::find_by_user(user_id)
            .await?
            .iter()
            .any(|l| l.provider_id == provider_id)
        {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "identity_link_provider_linked: you already have a link to this provider, \
                unlink it before linking another identity of it",
            ));
        }
        Ok(())
    }

    /// Remove an explicitly named identity using a client-retained operation ID.
    /// A retry observes its original result rather than minting another operation.
    pub async fn unlink(
        user_id: &str,
        session_id: &str,
        request: &rauthy_api_types::auth_providers::ProviderUnlinkRequest,
    ) -> Result<(), ErrorResponse> {
        use crate::entity::identity_link_observation::LinkAudit;
        use crate::entity::identity_link_unlink::UnlinkAdmission;
        if let Some(original) = LinkAudit::find(&request.operation_id).await? {
            original.matches_request(
                user_id,
                &request.provider_id,
                &request.subject,
                "unlinked",
            )?;
            return Ok(());
        }
        let provider = AuthProvider::find(&request.provider_id).await?;
        UnlinkAdmission {
            operation_id: &request.operation_id,
            user_id,
            session_id,
            provider_id: &request.provider_id,
            issuer: &provider.issuer,
            subject: &request.subject,
            observer: &crate::rauthy_config::RauthyConfig::get().issuer,
            observed_at: chrono::Utc::now().timestamp(),
        }
        .commit()
        .await
    }

    /// One unlink observation for each of `links`, for a deletion that removes them together
    /// with their user or their provider.
    pub(crate) fn audit_removal(links: &[Self], issuer: &str, now: i64) -> Vec<IdentityLinkAudit> {
        links
            .iter()
            .map(|l| IdentityLinkAudit {
                id: new_store_id(),
                user_id: l.user_id.clone(),
                provider_id: l.provider_id.clone(),
                issuer: issuer.to_string(),
                federation_uid: l.federation_uid.clone(),
                link_change: LinkChange::Unlinked.as_str().to_string(),
                observed_at: now,
                observer: Some(crate::rauthy_config::RauthyConfig::get().issuer.clone()),
                actor_session: None,
                lys_person: None,
                receipt: None,
                acknowledged_at: None,
                receipt_verified: false,
            })
            .collect()
    }

    /// The links of `user_id` with each one's audit state, the primary link first and the
    /// others oldest first.
    pub async fn find_for_response(
        user_id: &str,
    ) -> Result<Vec<ProviderLinkResponse>, ErrorResponse> {
        let user = User::find(user_id.to_string()).await?;
        let links = Self::find_by_user(user_id).await?;
        let audits = IdentityLinkAudit::find_by_user(user_id).await?;

        let mut res = Vec::with_capacity(links.len());
        for link in links {
            let provider_name = AuthProvider::find(&link.provider_id).await?.name;
            let audit = link_audit_state(&link, &audits);
            let primary = user.auth_provider_id.as_deref() == Some(link.provider_id.as_str())
                && user.federation_uid.as_deref() == Some(link.federation_uid.as_str());
            res.push(ProviderLinkResponse {
                provider_id: link.provider_id,
                provider_name,
                federation_uid: link.federation_uid,
                created: link.created,
                primary,
                audit,
            });
        }
        // stable: the others keep their order
        res.sort_by_key(|l| !l.primary);
        Ok(res)
    }
}

/// The audit state of `link`: the state of the latest link observation of this identity.
/// A link with no observation, as one carried over by the migration, reads as pending.
fn link_audit_state(link: &IdentityLink, audits: &[IdentityLinkAudit]) -> ProviderLinkAuditState {
    audits
        .iter()
        .filter(|a| {
            a.provider_id == link.provider_id
                && a.federation_uid == link.federation_uid
                && a.link_change == LinkChange::Linked.as_str()
        })
        .max_by_key(|a| a.observed_at)
        .map(IdentityLinkAudit::state)
        .unwrap_or(ProviderLinkAuditState::Pending)
}

fn refused_taken() -> ErrorResponse {
    ErrorResponse::new(
        ErrorResponseType::Forbidden,
        "identity_link_taken: this provider identity is linked to another account",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// Upstream's highest migration numbers at the commit the ablative branch is based on,
    /// v0.36.2.
    const BASE_HIGHEST_POSTGRES: u32 = 26;
    const BASE_HIGHEST_HIQLITE: u32 = 31;
    /// Upstream's highest postgres migration number on its main branch when these migrations
    /// were numbered, which a later rebase brings in.
    const UPSTREAM_MAIN_HIGHEST_POSTGRES: u32 = 30;

    fn migrations_dir(db: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations")
            .join(db)
    }

    /// Every migration in `dir` by number, refusing a number held twice.
    fn numbered(dir: &Path, prefix: &str) -> BTreeMap<u32, String> {
        let mut res = BTreeMap::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let rest = name.strip_prefix(prefix).unwrap();
            let (num, _) = rest.split_once('_').unwrap();
            let num: u32 = num.parse().unwrap();
            if let Some(other) = res.insert(num, name.clone()) {
                panic!("migration number {num} is held twice: {other} and {name}");
            }
        }
        res
    }

    fn apply_hiqlite_migrations(conn: &rusqlite::Connection, up_to: u32) {
        for (num, name) in numbered(&migrations_dir("hiqlite"), "") {
            if num > up_to {
                break;
            }
            let sql = std::fs::read_to_string(migrations_dir("hiqlite").join(&name)).unwrap();
            conn.execute_batch(&sql)
                .unwrap_or_else(|err| panic!("applying {name}: {err}"));
        }
    }

    fn identity_links_sql() -> String {
        std::fs::read_to_string(migrations_dir("hiqlite").join("32_identity_links.sql")).unwrap()
    }

    fn seed(conn: &rusqlite::Connection) {
        conn.execute_batch(
            r#"
INSERT INTO auth_providers (id, name, enabled, typ, issuer, authorization_endpoint,
    token_endpoint, userinfo_endpoint, client_id, scope, use_pkce, client_secret_basic,
    client_secret_post, auto_onboarding, auto_link)
VALUES ('google', 'Google', 1, 'google', 'https://accounts.test', 'https://a.test/auth',
    'https://a.test/token', 'https://a.test/userinfo', 'client', 'openid', 1, 0, 0, 0, 0);
INSERT INTO users (id, email, given_name, roles, enabled, email_verified, created_at,
    language, auth_provider_id, federation_uid)
VALUES ('userLinked', 'linked@test', 'Linked', '', 1, 1, 100, 'en', 'google', 'google-sub-1');
INSERT INTO users (id, email, given_name, roles, enabled, email_verified, created_at, language)
VALUES ('userLocal', 'local@test', 'Local', '', 1, 1, 200, 'en');
"#,
        )
        .unwrap();
    }

    fn links(conn: &rusqlite::Connection) -> Vec<(String, String, String, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT provider_id, federation_uid, user_id, created FROM identity_links \
                ORDER BY user_id",
            )
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn user_ids(conn: &rusqlite::Connection) -> Vec<String> {
        let mut stmt = conn.prepare("SELECT id FROM users ORDER BY id").unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn open_seeded() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        apply_hiqlite_migrations(&conn, BASE_HIGHEST_HIQLITE);
        seed(&conn);
        conn
    }

    /// ID001_LINK_NUMBERS: no migration number is held twice on either side, hiqlite's numbers
    /// run without a gap from 1 as it requires, and the identity_links migrations are the only
    /// fork migrations, each numbered above upstream's highest at the base.
    #[test]
    fn id001_link_numbers_are_unique_and_above_the_base() {
        println!("ID001_LINK_NUMBERS");
        let pg = numbered(&migrations_dir("postgres"), "V");
        let hql = numbered(&migrations_dir("hiqlite"), "");

        for (num, name) in &pg {
            println!("postgres {num}: {name}");
        }
        for (num, name) in &hql {
            println!("hiqlite {num}: {name}");
        }

        let hql_numbers: Vec<u32> = hql.keys().copied().collect();
        let expected: Vec<u32> = (1..=hql_numbers.len() as u32).collect();
        assert_eq!(
            hql_numbers, expected,
            "hiqlite migrations run from 1 without a gap"
        );

        let fork_pg: Vec<_> = pg.range(BASE_HIGHEST_POSTGRES + 1..).collect();
        assert_eq!(
            fork_pg.len(),
            2,
            "original and forward admission migrations"
        );
        assert_eq!(fork_pg[1].1, "V32__identity_link_admission.sql");
        let (pg_num, pg_name) = fork_pg[0];
        assert_eq!(pg_name, &format!("V{pg_num}__identity_links.sql"));
        assert!(
            *pg_num > UPSTREAM_MAIN_HIGHEST_POSTGRES,
            "the postgres identity_links migration is numbered above upstream main's highest"
        );

        let fork_hql: Vec<_> = hql.range(BASE_HIGHEST_HIQLITE + 1..).collect();
        assert_eq!(
            fork_hql.len(),
            1,
            "the original hiqlite migration stays unchanged"
        );
        let (hql_num, hql_name) = fork_hql[0];
        assert_eq!(*hql_num, BASE_HIGHEST_HIQLITE + 1);
        assert_eq!(hql_name, &format!("{hql_num}_identity_links.sql"));
    }

    /// ID001_LINK_MIGRATION: the migration keeps every user id and turns each existing provider
    /// pair into one link.
    #[test]
    fn id001_link_migration_preserves_ids_and_links() {
        println!("ID001_LINK_MIGRATION");
        let conn = open_seeded();
        let ids_before = user_ids(&conn);

        conn.execute_batch(&identity_links_sql()).unwrap();

        assert_eq!(user_ids(&conn), ids_before, "no user id changes");
        assert_eq!(
            links(&conn),
            vec![(
                "google".to_string(),
                "google-sub-1".to_string(),
                "userLinked".to_string(),
                100
            )],
            "the one existing pair becomes one link of the same user"
        );
        let (provider, uid): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT auth_provider_id, federation_uid FROM users WHERE id = 'userLinked'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(provider.as_deref(), Some("google"));
        assert_eq!(uid.as_deref(), Some("google-sub-1"));
    }

    /// ID001_LINK_MIGRATION: an interrupted migration leaves nothing behind, and running it
    /// again afterwards completes it.
    #[test]
    fn id001_link_migration_restarts_after_interruption() {
        println!("ID001_LINK_MIGRATION");
        let mut conn = open_seeded();
        let sql = identity_links_sql();

        {
            // the first statements run, then the process stops before the commit
            let txn = conn.transaction().unwrap();
            let (first_part, _) = sql.split_once("CREATE TABLE identity_link_audit").unwrap();
            txn.execute_batch(first_part).unwrap();
            drop(txn);
        }
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'identity_links'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(exists, 0, "an interrupted migration leaves no table");

        let txn = conn.transaction().unwrap();
        txn.execute_batch(&sql).unwrap();
        txn.commit().unwrap();
        assert_eq!(links(&conn).len(), 1);
    }

    /// ID001_LINK_MIGRATION: a schema the migration does not fit is refused by name, and the
    /// migration never runs twice over its own tables.
    #[test]
    fn id001_link_migration_refuses_incompatible_schemas_by_name() {
        println!("ID001_LINK_MIGRATION");
        let conn = open_seeded();
        conn.execute_batch(&identity_links_sql()).unwrap();
        let err = conn.execute_batch(&identity_links_sql()).unwrap_err();
        assert!(
            err.to_string().contains("identity_links"),
            "a second run names the table it refuses: {err}"
        );

        let foreign = rusqlite::Connection::open_in_memory().unwrap();
        foreign
            .execute_batch(
                "CREATE TABLE auth_providers (id TEXT PRIMARY KEY);\
                CREATE TABLE users (id TEXT PRIMARY KEY, created_at INTEGER);",
            )
            .unwrap();
        let err = foreign.execute_batch(&identity_links_sql()).unwrap_err();
        assert!(
            err.to_string().contains("auth_provider_id"),
            "a users table without the provider pair is refused by the column's name: {err}"
        );
    }

    /// ID001_LINK_REFUSAL: after the migration, one provider identity names one user only, and
    /// one user holds one identity per provider.
    #[test]
    fn id001_link_refusal_constraints_hold_in_storage() {
        println!("ID001_LINK_REFUSAL");
        let conn = open_seeded();
        conn.execute_batch(&identity_links_sql()).unwrap();

        let taken = conn.execute(
            "INSERT INTO identity_links (provider_id, federation_uid, user_id, created) \
            VALUES ('google', 'google-sub-1', 'userLocal', 300)",
            [],
        );
        assert!(
            taken.is_err(),
            "an owned provider identity is not linked again"
        );

        let second = conn.execute(
            "INSERT INTO identity_links (provider_id, federation_uid, user_id, created) \
            VALUES ('google', 'google-sub-2', 'userLinked', 300)",
            [],
        );
        assert!(second.is_err(), "a user holds one identity per provider");
        assert_eq!(links(&conn).len(), 1, "no unintended link");
    }

    #[test]
    fn a_link_reads_as_acknowledged_only_from_its_own_latest_observation() {
        let link = IdentityLink {
            provider_id: "google".to_string(),
            federation_uid: "sub".to_string(),
            user_id: "user".to_string(),
            created: 1,
        };
        let observation =
            |id: &str, change: LinkChange, at: i64, receipt: Option<&str>| IdentityLinkAudit {
                id: id.to_string(),
                user_id: "user".to_string(),
                provider_id: "google".to_string(),
                issuer: "https://accounts.test".to_string(),
                federation_uid: "sub".to_string(),
                link_change: change.as_str().to_string(),
                observed_at: at,
                observer: Some("https://observer.test".into()),
                actor_session: None,
                lys_person: None,
                receipt: receipt.map(String::from),
                acknowledged_at: receipt.map(|_| at),
                receipt_verified: receipt.is_some(),
            };

        assert_eq!(
            link_audit_state(&link, &[]),
            ProviderLinkAuditState::Pending
        );
        let audits = [
            observation("a", LinkChange::Linked, 1, Some("r1")),
            observation("b", LinkChange::Unlinked, 2, Some("r2")),
            observation("c", LinkChange::Linked, 3, None),
        ];
        assert_eq!(
            link_audit_state(&link, &audits),
            ProviderLinkAuditState::Pending,
            "a relink is pending although an earlier link was acknowledged"
        );
        assert_eq!(
            link_audit_state(&link, &audits[..1]),
            ProviderLinkAuditState::Acknowledged
        );
    }
}
