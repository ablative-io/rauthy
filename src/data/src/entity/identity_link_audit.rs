//! Immutable link observations retain original provenance and receiver acknowledgement.
use super::identity_link_receipt::VerifiedLinkReceipt;
use crate::database::DB;
use chrono::Utc;
use hiqlite::macros::params;
use rauthy_api_types::auth_providers::{
    ProviderLinkAuditResponse, ProviderLinkAuditState, ProviderLinkChange,
};
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};

/// Inserts one observation. `$1` id, `$2` user, `$3` provider, `$4` issuer, `$5` federation
/// uid, `$6` change, `$7` observed at, `$8` original observer.
pub(crate) static SQL_INSERT: &str = r#"
INSERT INTO identity_link_audit
(id, user_id, provider_id, issuer, federation_uid, link_change, observed_at, observer)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#;

/// A link or an unlink as the change it records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkChange {
    Linked,
    Unlinked,
}

impl LinkChange {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::Unlinked => "unlinked",
        }
    }
}

impl TryFrom<&str> for LinkChange {
    type Error = ErrorResponse;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "linked" => Ok(Self::Linked),
            "unlinked" => Ok(Self::Unlinked),
            _ => Err(ErrorResponse::new(
                ErrorResponseType::Internal,
                format!("identity_link_audit_corrupt: unknown link change '{value}'"),
            )),
        }
    }
}

/// One link or unlink observation, written in the same transaction as the change it records.
///
/// It stays pending until the receiver acknowledges it with its receipt. Its `id` is the stable
/// source operation id the receiver deduplicates on, so a redelivery never records a second
/// event, and only a stored receipt ever marks it acknowledged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, FromPgRow)]
pub struct IdentityLinkAudit {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    pub issuer: String,
    pub federation_uid: String,
    pub link_change: String,
    pub observed_at: i64,
    pub observer: Option<String>,
    pub actor_session: Option<String>,
    pub lys_person: Option<String>,
    pub receipt: Option<String>,
    pub acknowledged_at: Option<i64>,
    /// Legacy text receipts are not proof; only the verifier sets this marker.
    #[serde(default)]
    pub receipt_verified: bool,
}

impl IdentityLinkAudit {
    /// Every observation the receiver has not acknowledged yet, oldest first.
    pub async fn find_pending() -> Result<Vec<Self>, ErrorResponse> {
        let sql = r#"
SELECT * FROM identity_link_audit
WHERE receipt_verified = FALSE
ORDER BY observed_at ASC, id ASC"#;
        let res = if is_hiqlite() {
            DB::hql().query_as(sql, params!()).await?
        } else {
            DB::pg_query(sql, &[], 0).await?
        };
        Ok(res)
    }

    /// Every observation about `user_id`, oldest first.
    pub async fn find_by_user(user_id: &str) -> Result<Vec<Self>, ErrorResponse> {
        let sql = r#"
SELECT * FROM identity_link_audit
WHERE user_id = $1
ORDER BY observed_at ASC, id ASC"#;
        let res = if is_hiqlite() {
            DB::hql().query_as(sql, params!(user_id)).await?
        } else {
            DB::pg_query(sql, &[&user_id], 0).await?
        };
        Ok(res)
    }

    pub async fn find(id: &str) -> Result<Option<Self>, ErrorResponse> {
        let sql = "SELECT * FROM identity_link_audit WHERE id = $1";
        let res = if is_hiqlite() {
            DB::hql().query_as_optional(sql, params!(id)).await?
        } else {
            DB::pg_query_opt(sql, &[&id]).await?
        };
        Ok(res)
    }

    /// Bind an operation to the first authoritative person lookup before network delivery.
    /// A retry refuses a different mapping instead of moving a previously admitted event.
    pub async fn bind_person(id: &str, user: &str, person: &str) -> Result<Self, ErrorResponse> {
        let sql = "UPDATE identity_link_audit SET lys_person=$1 WHERE id=$2 AND user_id=$3 AND lys_person IS NULL";
        DB::pg_execute(sql, &[&person, &id, &user]).await?;
        let row = Self::find(id).await?.ok_or_else(|| {
            ErrorResponse::new(
                ErrorResponseType::NotFound,
                format!("identity_link_audit_unknown: operation '{id}'"),
            )
        })?;
        if row.user_id != user || row.lys_person.as_deref() != Some(person) {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!(
                    "identity_link_audit_person_conflict: operation '{id}' already names another account or person"
                ),
            ));
        }
        Ok(row)
    }

    /// Only an observation verified against the provisioned Lys service can be acknowledged.
    /// A retry may carry a newer inclusion checkpoint for the same signed event.
    pub async fn acknowledge(verified: &VerifiedLinkReceipt) -> Result<Self, ErrorResponse> {
        let id = verified.operation();
        let user = verified.user();
        let person = verified.person();
        let receipt = verified.evidence();
        let now = Utc::now().timestamp();
        let sql = "UPDATE identity_link_audit SET receipt=$1,acknowledged_at=$2,receipt_verified=TRUE WHERE id=$3 AND user_id=$4 AND lys_person=$5 AND receipt_verified=FALSE";
        DB::pg_execute(sql, &[&receipt, &now, &id, &user, &person]).await?;
        let row = Self::find(id).await?.ok_or_else(|| {
            ErrorResponse::new(
                ErrorResponseType::NotFound,
                format!("identity_link_audit_unknown: operation '{id}'"),
            )
        })?;
        if row.user_id != user || row.lys_person.as_deref() != Some(person) {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!(
                    "identity_link_audit_person_conflict: operation '{id}' changed account or person"
                ),
            ));
        }
        let stored = row.receipt.as_deref().ok_or_else(|| ErrorResponse::new(
            ErrorResponseType::Internal,
            format!("identity_link_audit_ack_missing: operation '{id}' has no stored acknowledgement"),
        ))?;
        let stored: super::identity_link_receipt::ReceiverEvidence = serde_json::from_str(stored)
            .map_err(|error| {
            ErrorResponse::new(
                ErrorResponseType::Internal,
                format!("identity_link_audit_receipt_unverified: operation '{id}': {error}"),
            )
        })?;
        if stored.message != verified.message() {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!(
                    "identity_link_audit_receipt_conflict: operation '{id}' was acknowledged by another signed event"
                ),
            ));
        }
        Ok(row)
    }

    pub fn state(&self) -> ProviderLinkAuditState {
        if self.receipt_verified && self.acknowledged_at.is_some() && self.receipt.is_some() {
            ProviderLinkAuditState::Acknowledged
        } else {
            ProviderLinkAuditState::Pending
        }
    }

    pub fn into_response(self) -> Result<ProviderLinkAuditResponse, ErrorResponse> {
        let state = self.state();
        let change = match LinkChange::try_from(self.link_change.as_str())? {
            LinkChange::Linked => ProviderLinkChange::Linked,
            LinkChange::Unlinked => ProviderLinkChange::Unlinked,
        };
        Ok(ProviderLinkAuditResponse {
            source_operation_id: self.id,
            user_id: self.user_id,
            change,
            provider_id: self.provider_id,
            issuer: self.issuer,
            subject: self.federation_uid,
            observer: self.observer,
            observed_at: self.observed_at,
            state,
            receipt: self.receipt,
            acknowledged_at: self.acknowledged_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(receipt: Option<&str>) -> IdentityLinkAudit {
        IdentityLinkAudit {
            id: "op1".to_string(),
            user_id: "user1".to_string(),
            provider_id: "provider1".to_string(),
            issuer: "https://accounts.test".to_string(),
            federation_uid: "subject1".to_string(),
            link_change: LinkChange::Linked.as_str().to_string(),
            observed_at: 1,
            observer: Some("https://observer.test".into()),
            actor_session: None,
            lys_person: None,
            receipt: receipt.map(String::from),
            acknowledged_at: receipt.map(|_| 2),
            receipt_verified: receipt.is_some(),
        }
    }

    /// ID001_LINK_AUDIT: an observation reads as acknowledged only once it holds a receipt, the
    /// same receipt answers again, and a different one is refused.
    #[test]
    fn id001_link_audit_state_follows_the_receipt_only() {
        println!("ID001_LINK_AUDIT");
        assert_eq!(observation(None).state(), ProviderLinkAuditState::Pending);

        let mut without_receipt = observation(None);
        without_receipt.acknowledged_at = Some(2);
        assert_eq!(
            without_receipt.state(),
            ProviderLinkAuditState::Pending,
            "a time without a receipt is never a completed audit"
        );

        let acknowledged = observation(Some("receipt-1"));
        assert_eq!(acknowledged.state(), ProviderLinkAuditState::Acknowledged);
        let mut legacy = observation(Some("receipt-1"));
        legacy.receipt_verified = false;
        assert_eq!(legacy.state(), ProviderLinkAuditState::Pending);
    }

    #[test]
    fn link_changes_round_trip_and_refuse_unknown_values() {
        for change in [LinkChange::Linked, LinkChange::Unlinked] {
            assert_eq!(LinkChange::try_from(change.as_str()).unwrap(), change);
        }
        assert!(LinkChange::try_from("merged").is_err());
    }
}
