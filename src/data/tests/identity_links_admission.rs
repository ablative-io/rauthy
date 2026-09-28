//! PostgreSQL transaction legs execute the production admission SQL against an isolated schema.
use cryptr::utils::secure_random_alnum;
use rauthy_data::entity::identity_link_sql as sql;
use std::error::Error;
use tokio_postgres::{Client, NoTls};

type TestResult = Result<(), Box<dyn Error>>;

struct Fixture {
    client: Client,
    schema: String,
    connection: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}

impl Fixture {
    async fn new(first: &str, second: &str) -> Result<Self, Box<dyn Error>> {
        let db = Self::legacy(first).await?;
        db.client
            .batch_execute(&format!(
                "BEGIN; {} COMMIT;",
                include_str!("../../../migrations/postgres/V32__identity_link_admission.sql")
            ))
            .await?;
        db.client.execute("INSERT INTO identity_link_intents(id,user_id,session_id,provider_id,callback_id,nonce,created_at,expires_at,reauthenticated_at)
            VALUES ('intent','person-a','session-a',$1,'callback','nonce',100,300,101)", &[&second]).await?;
        Ok(db)
    }

    async fn legacy(first: &str) -> Result<Self, Box<dyn Error>> {
        let url = std::env::var("IDENTITY_TEST_DATABASE_URL").map_err(
            |_| "IDENTITY_TEST_DATABASE_URL is required; no identity transaction test is skipped",
        )?;
        let (client, connection) = tokio_postgres::connect(&url, NoTls).await?;
        let connection = tokio::spawn(connection);
        let schema = format!("identity_test_{}", secure_random_alnum(20).to_lowercase());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await?;
        client.batch_execute("CREATE TABLE auth_providers(id TEXT PRIMARY KEY, enabled BOOLEAN NOT NULL, issuer TEXT NOT NULL);
            CREATE TABLE users(id TEXT PRIMARY KEY, auth_provider_id TEXT, federation_uid TEXT,
            enabled BOOLEAN NOT NULL, user_expires BIGINT, password TEXT, password_expires BIGINT,
            created_at BIGINT NOT NULL DEFAULT 0);
            CREATE TABLE passkeys(user_id TEXT NOT NULL);
            CREATE TABLE sessions(id TEXT PRIMARY KEY,user_id TEXT,state TEXT,exp BIGINT);
            INSERT INTO auth_providers VALUES ('google',TRUE,'google-issuer'),('github',TRUE,'github-issuer');
            INSERT INTO sessions VALUES ('session-a','person-a','auth',1000);").await?;
        client
            .execute(
                "INSERT INTO users VALUES ('person-a',$1,'first-sub',TRUE,NULL,NULL,NULL,0)",
                &[&first],
            )
            .await?;
        client
            .batch_execute(&format!(
                "BEGIN; {} COMMIT;",
                include_str!("../../../migrations/postgres/V31__identity_links.sql")
            ))
            .await?;
        Ok(Self {
            client,
            schema,
            connection,
        })
    }

    async fn count(&self, table: &str) -> Result<i64, tokio_postgres::Error> {
        Ok(self
            .client
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await?
            .get(0))
    }

    async fn finish(self) -> TestResult {
        self.client
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await?;
        self.close().await
    }

    async fn close(self) -> TestResult {
        drop(self.client);
        self.connection.await??;
        Ok(())
    }

    async fn reconnect(&self) -> Result<Self, Box<dyn Error>> {
        let url = std::env::var("IDENTITY_TEST_DATABASE_URL")?;
        let (client, connection) = tokio_postgres::connect(&url, NoTls).await?;
        let connection = tokio::spawn(connection);
        client
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .await?;
        Ok(Self {
            client,
            schema: self.schema.clone(),
            connection,
        })
    }

    async fn admit(
        &mut self,
        provider: &str,
        callback: &str,
        nonce: &str,
        now: i64,
        operation: &str,
        prefix: usize,
    ) -> Result<(), tokio_postgres::Error> {
        let tx = self.client.transaction().await?;
        tx.execute(sql::LOCK_PERSON, &[&"person-a"]).await?;
        tx.execute(
            sql::CONSUME,
            &[
                &operation,
                &"intent",
                &"person-a",
                &"session-a",
                &provider,
                &callback,
                &nonce,
                &now,
            ],
        )
        .await?;
        if prefix >= 2 {
            tx.execute(
                sql::AUDIT_LINK,
                &[
                    &operation,
                    &"intent",
                    &provider,
                    &"issuer",
                    &"second-sub",
                    &"session-a",
                    &"observer",
                    &now,
                ],
            )
            .await?;
        }
        if prefix >= 3 {
            tx.execute(sql::INSERT_LINK, &[&operation]).await?;
        }
        if prefix >= 4 {
            tx.execute(sql::PROJECT_PRIMARY, &[&"person-a"]).await?;
        }
        if prefix == 5 {
            tx.commit().await
        } else {
            tx.rollback().await
        }
    }

    async fn unlink(
        &mut self,
        provider: &str,
        subject: &str,
        operation: &str,
    ) -> Result<(), tokio_postgres::Error> {
        let tx = self.client.transaction().await?;
        tx.execute(sql::LOCK_PERSON, &[&"person-a"]).await?;
        tx.execute(
            sql::AUDIT_UNLINK,
            &[
                &operation,
                &"person-a",
                &provider,
                &"issuer",
                &subject,
                &"session-a",
                &"observer",
                &150_i64,
            ],
        )
        .await?;
        tx.execute(sql::DELETE_LINK, &[&"person-a", &provider, &subject])
            .await?;
        tx.execute(sql::PROJECT_PRIMARY, &[&"person-a"]).await?;
        tx.commit().await
    }
}

#[tokio::test]
async fn pair_both_orders_replay_and_primary_are_durable() -> TestResult {
    for (first, second) in [("google", "github"), ("github", "google")] {
        let mut db = Fixture::new(first, second).await?;
        db.admit(second, "callback", "nonce", 150, "operation", 5)
            .await?;
        assert_eq!(db.count("users").await?, 1);
        assert_eq!(db.count("identity_links").await?, 2);
        assert_eq!(
            db.client
                .query_one(
                    "SELECT auth_provider_id FROM users WHERE id='person-a'",
                    &[]
                )
                .await?
                .get::<_, String>(0),
            first
        );
        assert!(
            db.admit(second, "callback", "nonce", 151, "repeat", 5)
                .await
                .is_err()
        );
        assert_eq!(db.count("identity_link_audit").await?, 1);
        // A second connection sees the committed relation, not the first connection's state.
        let url = std::env::var("IDENTITY_TEST_DATABASE_URL")?;
        let (read, connection) = tokio_postgres::connect(&url, NoTls).await?;
        let driver = tokio::spawn(connection);
        assert_eq!(
            read.query_one(
                &format!("SELECT count(*) FROM {}.identity_links", db.schema),
                &[]
            )
            .await?
            .get::<_, i64>(0),
            2
        );
        drop(read);
        driver.await??;
        db.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn binding_and_expiry_refusals_leave_no_half_state() -> TestResult {
    let mut legs = 0;
    for (provider, callback, nonce, now) in [
        ("google", "callback", "nonce", 150),
        ("github", "wrong", "nonce", 150),
        ("github", "callback", "wrong", 150),
        ("github", "callback", "nonce", 300),
    ] {
        let mut db = Fixture::new("google", "github").await?;
        assert!(
            db.admit(provider, callback, nonce, now, "operation", 5)
                .await
                .is_err()
        );
        assert_eq!(db.count("identity_link_audit").await?, 0);
        assert_eq!(db.count("identity_links").await?, 1);
        assert_eq!(
            db.client
                .query_one(
                    "SELECT consumed_operation_id FROM identity_link_intents",
                    &[]
                )
                .await?
                .get::<_, Option<String>>(0),
            None
        );
        db.finish().await?;
        legs += 1;
    }
    assert_eq!(legs, 4);
    Ok(())
}

#[tokio::test]
async fn revoked_session_user_and_provider_refuse_admission() -> TestResult {
    let mut legs = 0;
    for change in [
        "UPDATE sessions SET state='logged_out'",
        "UPDATE sessions SET user_id='other'",
        "UPDATE sessions SET exp=150",
        "UPDATE users SET enabled=FALSE",
        "UPDATE users SET user_expires=150",
        "UPDATE auth_providers SET enabled=FALSE WHERE id='github'",
    ] {
        let mut db = Fixture::new("google", "github").await?;
        db.client.batch_execute(change).await?;
        assert!(
            db.admit("github", "callback", "nonce", 150, "operation", 5)
                .await
                .is_err()
        );
        assert_eq!(db.count("identity_link_audit").await?, 0);
        assert_eq!(db.count("identity_links").await?, 1);
        db.finish().await?;
        legs += 1;
    }
    assert_eq!(legs, 6);
    Ok(())
}

#[tokio::test]
async fn interrupted_prefixes_roll_back_then_original_request_succeeds() -> TestResult {
    let mut legs = 0;
    for prefix in 1..=4 {
        let mut db = Fixture::new("google", "github").await?;
        db.admit("github", "callback", "nonce", 150, "operation", prefix)
            .await?;
        assert_eq!(db.count("identity_link_audit").await?, 0);
        assert_eq!(db.count("identity_links").await?, 1);
        db.admit("github", "callback", "nonce", 150, "operation", 5)
            .await?;
        assert_eq!(db.count("identity_link_audit").await?, 1);
        db.finish().await?;
        legs += 1;
    }
    assert_eq!(legs, 4);
    Ok(())
}

#[tokio::test]
async fn final_method_counts_enabled_providers_and_actual_usable_credentials() -> TestResult {
    let mut legs = 0;
    for (change, allowed) in [
        ("SELECT 1", false),
        ("UPDATE users SET password='hash'", true),
        (
            "UPDATE users SET password='hash',password_expires=150",
            false,
        ),
        ("INSERT INTO passkeys VALUES ('person-a')", true),
        ("INSERT INTO passkeys VALUES ('other')", false),
    ] {
        let mut db = Fixture::new("google", "github").await?;
        db.client.batch_execute(change).await?;
        assert_eq!(
            db.unlink("google", "first-sub", "removal").await.is_ok(),
            allowed
        );
        assert_eq!(db.count("identity_link_audit").await?, i64::from(allowed));
        db.finish().await?;
        legs += 1;
    }
    let mut db = Fixture::new("google", "github").await?;
    db.admit("github", "callback", "nonce", 150, "operation", 5)
        .await?;
    db.client
        .batch_execute("UPDATE auth_providers SET enabled=FALSE WHERE id='github'")
        .await?;
    assert!(db.unlink("google", "first-sub", "blocked").await.is_err());
    db.client
        .batch_execute("UPDATE auth_providers SET enabled=TRUE WHERE id='github'")
        .await?;
    db.unlink("google", "first-sub", "removal").await?;
    assert!(
        db.unlink("github", "second-sub", "final-removal")
            .await
            .is_err()
    );
    assert_eq!(db.count("identity_links").await?, 1);
    db.finish().await?;
    assert_eq!(legs, 5);
    Ok(())
}

#[tokio::test]
async fn old_proof_refuses_but_same_second_fresh_proof_admits() -> TestResult {
    let mut db = Fixture::new("google", "github").await?;
    db.client
        .batch_execute("DELETE FROM identity_link_intents")
        .await?;
    db.client
        .execute(
            sql::RECORD_REAUTHENTICATION,
            &[&"old", &100_i64, &"session-a", &"person-a"],
        )
        .await?;
    db.client
        .execute(
            sql::PREPARE_INTENT,
            &[
                &"intent",
                &"person-a",
                &"session-a",
                &"github",
                &"callback",
                &"nonce",
                &100_i64,
                &300_i64,
            ],
        )
        .await?;
    db.client
        .execute(
            sql::ACTIVATE_INTENT,
            &[&"intent", &"person-a", &"session-a", &"github", &101_i64],
        )
        .await?;
    assert!(
        db.admit("github", "callback", "nonce", 101, "operation", 5)
            .await
            .is_err()
    );
    db.client
        .execute(
            sql::RECORD_REAUTHENTICATION,
            &[&"new", &100_i64, &"session-a", &"person-a"],
        )
        .await?;
    db.client
        .execute(
            sql::ACTIVATE_INTENT,
            &[&"intent", &"person-a", &"session-a", &"github", &101_i64],
        )
        .await?;
    db.admit("github", "callback", "nonce", 101, "operation", 5)
        .await?;
    db.finish().await
}

#[tokio::test]
async fn forward_migration_refuses_half_pairs_without_changing_applied_history() -> TestResult {
    for malformed in [
        "UPDATE users SET auth_provider_id=NULL",
        "UPDATE users SET federation_uid=NULL",
    ] {
        let db = Fixture::legacy("google").await?;
        db.client.batch_execute(malformed).await?;
        db.client.batch_execute("BEGIN").await?;
        let result = db
            .client
            .batch_execute(include_str!(
                "../../../migrations/postgres/V32__identity_link_admission.sql"
            ))
            .await;
        assert!(result.is_err());
        db.client.batch_execute("ROLLBACK").await?;
        assert_eq!(db.count("identity_links").await?, 1);
        assert_eq!(db.client.query_one("SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='identity_link_format'",&[]).await?.get::<_,i64>(0),0);
        db.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_callbacks_consume_the_intent_once() -> TestResult {
    let mut first = Fixture::new("google", "github").await?;
    let mut second = first.reconnect().await?;
    let (left, right) = tokio::join!(
        first.admit("github", "callback", "nonce", 150, "left", 5),
        second.admit("github", "callback", "nonce", 150, "right", 5),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    assert_eq!(first.count("identity_links").await?, 2);
    assert_eq!(first.count("identity_link_audit").await?, 1);
    second.close().await?;
    first.finish().await
}

#[tokio::test]
async fn concurrent_removals_cannot_remove_the_final_method() -> TestResult {
    let mut first = Fixture::new("google", "github").await?;
    first
        .admit("github", "callback", "nonce", 150, "linked", 5)
        .await?;
    let mut second = first.reconnect().await?;
    let (left, right) = tokio::join!(
        first.unlink("google", "first-sub", "remove-google"),
        second.unlink("github", "second-sub", "remove-github"),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    assert_eq!(first.count("identity_links").await?, 1);
    assert_eq!(first.count("identity_link_audit").await?, 2);
    let primary_matches: i64 = first.client.query_one(
        "SELECT count(*) FROM users u JOIN identity_links l ON l.user_id=u.id AND l.provider_id=u.auth_provider_id AND l.federation_uid=u.federation_uid", &[],
    ).await?.get(0);
    assert_eq!(primary_matches, 1);
    second.close().await?;
    first.finish().await
}
