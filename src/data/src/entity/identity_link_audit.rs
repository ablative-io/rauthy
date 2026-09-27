use crate::database::DB;
use crate::rauthy_config::RauthyConfig;
use chrono::Utc;
use hiqlite::macros::params;
use rauthy_api_types::auth_providers::{
    ProviderLinkAuditResponse, ProviderLinkAuditState, ProviderLinkChange,
};
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::{Deserialize, Serialize};

/// The longest receipt the receiver may acknowledge an observation with.
pub const RECEIPT_MAX_BYTES: usize = 16384;

/// Inserts one observation. `$1` id, `$2` user, `$3` provider, `$4` issuer, `$5` federation
/// uid, `$6` change, `$7` observed at.
pub(crate) static SQL_INSERT: &str = r#"
INSERT INTO identity_link_audit
(id, user_id, provider_id, issuer, federation_uid, link_change, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)"#;

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
    pub receipt: Option<String>,
    pub acknowledged_at: Option<i64>,
}

impl IdentityLinkAudit {
    /// Every observation the receiver has not acknowledged yet, oldest first.
    pub async fn find_pending() -> Result<Vec<Self>, ErrorResponse> {
        let sql = r#"
SELECT * FROM identity_link_audit
WHERE acknowledged_at IS NULL
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

    /// Records the receiver's receipt for the observation `id`.
    ///
    /// The same receipt again answers the stored observation and changes nothing. A different
    /// receipt for an acknowledged observation is refused, so an observation is never
    /// acknowledged twice.
    pub async fn acknowledge(id: &str, receipt: &str) -> Result<Self, ErrorResponse> {
        validate_receipt(receipt)?;

        let now = Utc::now().timestamp();
        let sql = r#"
UPDATE identity_link_audit
SET receipt = $1, acknowledged_at = $2
WHERE id = $3 AND acknowledged_at IS NULL"#;
        if is_hiqlite() {
            DB::hql().execute(sql, params!(receipt, now, id)).await?;
        } else {
            DB::pg_execute(sql, &[&receipt, &now, &id]).await?;
        }

        let Some(slf) = Self::find(id).await? else {
            return Err(ErrorResponse::new(
                ErrorResponseType::NotFound,
                "identity_link_audit_unknown: no link observation has this id",
            ));
        };
        slf.check_receipt(receipt)?;
        Ok(slf)
    }

    /// Refuses `receipt` unless it is the one this observation was acknowledged with.
    pub fn check_receipt(&self, receipt: &str) -> Result<(), ErrorResponse> {
        if self.receipt.as_deref() == Some(receipt) {
            Ok(())
        } else {
            Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "identity_link_audit_receipt_conflict: this observation was already \
                acknowledged with a different receipt",
            ))
        }
    }

    pub fn state(&self) -> ProviderLinkAuditState {
        if self.acknowledged_at.is_some() && self.receipt.is_some() {
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
            observer: RauthyConfig::get().issuer.clone(),
            observed_at: self.observed_at,
            state,
            receipt: self.receipt,
            acknowledged_at: self.acknowledged_at,
        })
    }
}

/// Refuses an empty receipt, one longer than [`RECEIPT_MAX_BYTES`], or one holding anything
/// other than printable ASCII.
pub fn validate_receipt(receipt: &str) -> Result<(), ErrorResponse> {
    if receipt.is_empty()
        || receipt.len() > RECEIPT_MAX_BYTES
        || !receipt.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!(
                "identity_link_audit_receipt_invalid: a receipt is 1 to {RECEIPT_MAX_BYTES} \
                bytes of printable ASCII without spaces"
            ),
        ));
    }
    Ok(())
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
            receipt: receipt.map(String::from),
            acknowledged_at: receipt.map(|_| 2),
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
        assert!(acknowledged.check_receipt("receipt-1").is_ok());
        let err = acknowledged.check_receipt("receipt-2").unwrap_err();
        assert!(
            err.message
                .starts_with("identity_link_audit_receipt_conflict")
        );
    }

    #[test]
    fn receipts_are_bounded_printable_ascii() {
        assert!(validate_receipt("r3ceipt:+/=").is_ok());
        assert!(validate_receipt("").is_err());
        assert!(validate_receipt("has space").is_err());
        assert!(validate_receipt("line\nbreak").is_err());
        assert!(validate_receipt(&"a".repeat(RECEIPT_MAX_BYTES)).is_ok());
        assert!(validate_receipt(&"a".repeat(RECEIPT_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn link_changes_round_trip_and_refuse_unknown_values() {
        for change in [LinkChange::Linked, LinkChange::Unlinked] {
            assert_eq!(LinkChange::try_from(change.as_str()).unwrap(), change);
        }
        assert!(LinkChange::try_from("merged").is_err());
    }
}
