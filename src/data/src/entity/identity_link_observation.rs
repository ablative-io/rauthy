//! Durable link observations remain pending until Lys acknowledges the exact operation.
use crate::database::DB;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};

/// Storage shape includes original evidence and acknowledgement, never credentials.
#[derive(Clone, Serialize, Deserialize, FromPgRow)]
pub struct LinkAudit {
    pub operation_id: String,
    pub user_id: String,
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    pub change: String,
    pub actor_session: String,
    pub observer: String,
    pub observed_at: i64,
    pub lys_person: Option<String>,
    pub receipt: Option<String>,
    pub acknowledged_at: Option<i64>,
}

impl LinkAudit {
    /// Read the original operation, including after an uncertain write outcome.
    ///
    /// # Errors
    /// Propagates an authoritative storage error rather than reporting absence.
    pub async fn find(operation: &str) -> Result<Option<Self>, ErrorResponse> {
        let sql = "SELECT id AS operation_id,user_id,provider_id,issuer,federation_uid AS subject,link_change AS change,actor_session,observer,observed_at,lys_person,receipt,acknowledged_at FROM identity_link_audit WHERE id=$1";
        DB::pg_query_opt(sql, &[&operation]).await
    }

    /// Read one person's operations for their own account display.
    ///
    /// # Errors
    /// Propagates an authoritative storage error.
    pub async fn for_user(user: &str) -> Result<Vec<Self>, ErrorResponse> {
        let sql = "SELECT id AS operation_id,user_id,provider_id,issuer,federation_uid AS subject,link_change AS change,actor_session,observer,observed_at,lys_person,receipt,acknowledged_at FROM identity_link_audit WHERE user_id=$1 ORDER BY observed_at,id";
        DB::pg_query(sql, &[&user], 2).await
    }

    /// A repeated operation can only recover its exact original request.
    ///
    /// # Errors
    /// Refuses a reused operation id naming another person, provider or subject.
    pub fn matches_request(
        &self,
        user: &str,
        provider: &str,
        subject: &str,
        change: &str,
    ) -> Result<(), ErrorResponse> {
        if self.user_id != user
            || self.provider_id != provider
            || self.subject != subject
            || self.change != change
        {
            return Err(ErrorResponse::new(
                ErrorResponseType::Forbidden,
                format!(
                    "identity link operation '{}' is already bound to another request",
                    self.operation_id
                ),
            ));
        }
        Ok(())
    }
}
