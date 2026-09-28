//! Refuse unknown identity-link formats before any migration can change storage.
use crate::database::DB;
use hiqlite::macros::params;
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::Deserialize;

/// The identity-link storage contract, independent of the upstream release number.
pub const SUPPORTED: i64 = 1;

#[derive(Deserialize, FromPgRow)]
pub struct FormatVersion {
    pub version: i64,
}

/// Absence is the legacy format; read failures never mean absence.
///
/// # Errors
/// Refuses a malformed or unsupported version, or an unreadable catalogue.
pub async fn check_before_migration() -> Result<(), ErrorResponse> {
    let exists = if is_hiqlite() {
        !DB::hql()
            .query_raw(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='identity_link_format'",
                params!(),
            )
            .await?
            .is_empty()
    } else {
        !DB::pg_query_rows("SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='identity_link_format'", &[], 1).await?.is_empty()
    };
    if !exists {
        return Ok(());
    }
    let rows: Vec<FormatVersion> = if is_hiqlite() {
        DB::hql()
            .query_as(
                "SELECT version FROM identity_link_format WHERE id=1",
                params!(),
            )
            .await?
    } else {
        DB::pg_query(
            "SELECT version FROM identity_link_format WHERE id=1",
            &[],
            1,
        )
        .await?
    };
    validate(&rows)
}

/// Legacy users with half a provider pair cannot be represented without guessing.
#[derive(Deserialize, FromPgRow)]
struct MalformedUser {
    id: String,
}

/// Refuse malformed legacy rows by identity before either migration runner writes.
///
/// # Errors
/// Names every malformed user ID; catalogue and row read errors propagate.
pub async fn check_legacy_pairs() -> Result<(), ErrorResponse> {
    let exists = if is_hiqlite() {
        !DB::hql()
            .query_raw(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users'",
                params!(),
            )
            .await?
            .is_empty()
    } else {
        !DB::pg_query_rows(
            "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='users'",
            &[], 1,
        ).await?.is_empty()
    };
    if !exists {
        return Ok(());
    }
    let sql = "SELECT id FROM users WHERE (auth_provider_id IS NULL AND federation_uid IS NOT NULL) OR (auth_provider_id IS NOT NULL AND federation_uid IS NULL) ORDER BY id";
    let rows: Vec<MalformedUser> = if is_hiqlite() {
        DB::hql().query_as(sql, params!()).await?
    } else {
        DB::pg_query(sql, &[], 1).await?
    };
    if rows.is_empty() {
        return Ok(());
    }
    Err(ErrorResponse::new(
        ErrorResponseType::BadRequest,
        format!(
            "identity_link_migration refused: incomplete provider identity on users [{}]",
            rows.into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ))
}

/// Validate a source or destination format without modifying it.
///
/// # Errors
/// Refuses a missing marker or unsupported version by name.
pub fn validate(rows: &[FormatVersion]) -> Result<(), ErrorResponse> {
    match rows {
        [version] if version.version == SUPPORTED => Ok(()),
        [version] => Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            format!(
                "identity_link_format version {} is unsupported; this binary supports {SUPPORTED}",
                version.version
            ),
        )),
        _ => Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "identity_link_format must contain exactly one version marker",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{FormatVersion, SUPPORTED, validate};
    #[test]
    fn format_refusals_name_stored_and_supported_versions() {
        assert!(validate(&[FormatVersion { version: SUPPORTED }]).is_ok());
        for version in [0, SUPPORTED + 1] {
            let result = validate(&[FormatVersion { version }]);
            assert!(result.is_err());
            if let Err(error) = result {
                assert!(error.message.contains(&format!("version {version}")));
                assert!(error.message.contains("supports 1"));
            }
        }
        assert!(validate(&[]).is_err());
    }
}
