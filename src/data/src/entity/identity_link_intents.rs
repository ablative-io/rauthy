//! Durable target-bound link intentions require actual reauthentication after preparation.
use crate::database::DB;
use crate::entity::identity_link_sql;
use chrono::Utc;
use cryptr::utils::secure_random_alnum;
use rauthy_common::constants::UPSTREAM_AUTH_CALLBACK_TIMEOUT_SECS;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};

/// Server-owned evidence. No HTTP request can supply the reauthentication time.
#[derive(Clone, Serialize, Deserialize, FromPgRow)]
pub struct LinkIntent {
    pub id: String,
    pub user_id: String,
    pub session_id: String,
    pub provider_id: String,
    pub callback_id: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub prior_auth_proof: Option<String>,
    pub reauthenticated_at: Option<i64>,
    pub consumed_operation_id: Option<String>,
}

impl LinkIntent {
    /// Prepare before reauthentication; capture the old proof inside this write.
    ///
    /// # Errors
    /// Refuses an invalid session or target and propagates durable write failure.
    pub async fn prepare(user: &str, session: &str, provider: &str) -> Result<Self, ErrorResponse> {
        let now = Utc::now().timestamp();
        let id = secure_random_alnum(32);
        let callback = secure_random_alnum(32);
        let nonce = secure_random_alnum(32);
        let expires = now + i64::from(UPSTREAM_AUTH_CALLBACK_TIMEOUT_SECS);
        let sql = identity_link_sql::PREPARE_INTENT;
        {
            DB::pg_execute(
                sql,
                &[
                    &id, &user, &session, &provider, &callback, &nonce, &now, &expires,
                ],
            )
            .await?;
        }
        Self::find(&id).await
    }

    /// Read the original durable intent; absence and storage failure are refusals.
    ///
    /// # Errors
    /// Refuses a missing intent by ID or propagates the authoritative read error.
    pub async fn find(id: &str) -> Result<Self, ErrorResponse> {
        let sql: &str = "SELECT * FROM identity_link_intents WHERE id=$1";
        let found: Option<Self> = { DB::pg_query_opt(sql, &[&id]).await? };
        found.ok_or_else(|| {
            ErrorResponse::new(
                ErrorResponseType::NotFound,
                format!("identity link intent '{id}' was not found"),
            )
        })
    }

    /// Activate only after a fresh proof for this same session and person.
    ///
    /// # Errors
    /// Refuses an expired, used, mismatched or unreauthenticated intent by ID.
    pub async fn activate(
        id: &str,
        user: &str,
        session: &str,
        provider: &str,
    ) -> Result<Self, ErrorResponse> {
        let now = Utc::now().timestamp();
        let sql = identity_link_sql::ACTIVATE_INTENT;
        {
            DB::pg_execute(sql, &[&id, &user, &session, &provider, &now]).await?;
        }
        let intent = Self::find(id).await?;
        intent.validate(user, session, provider, now)?;
        Ok(intent)
    }

    /// Check all durable bounds before contacting the target provider.
    ///
    /// # Errors
    /// Refuses a mismatched, expired, unreauthenticated or consumed intent.
    pub fn validate(
        &self,
        user: &str,
        session: &str,
        provider: &str,
        now: i64,
    ) -> Result<(), ErrorResponse> {
        let reason =
            if self.user_id != user || self.session_id != session || self.provider_id != provider {
                Some("target or session mismatch")
            } else if self.expires_at <= now {
                Some("expired")
            } else if self.consumed_operation_id.is_some() {
                Some("already consumed")
            } else if self.reauthenticated_at.is_none() {
                Some("fresh sign-in required")
            } else {
                None
            };
        match reason {
            Some(reason) => Err(ErrorResponse::new(
                ErrorResponseType::PreconditionRequired,
                format!("identity link intent '{}': {reason}", self.id),
            )),
            None => Ok(()),
        }
    }
}

/// Record a completed credential ceremony, never a silent session refresh.
///
/// # Errors
/// Refuses if the authenticated session is absent or storage cannot record proof.
pub async fn record_reauthentication(session: &str, user: &str) -> Result<(), ErrorResponse> {
    let now = Utc::now().timestamp();
    let proof = secure_random_alnum(32);
    let sql = identity_link_sql::RECORD_REAUTHENTICATION;
    let changed = { DB::pg_execute(sql, &[&proof, &now, &session, &user]).await? > 0 };
    if !changed {
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            format!(
                "cannot record identity link reauthentication for user '{user}': authenticated session absent"
            ),
        ));
    }
    Ok(())
}
