//! Read provisioned receiver trust; absent configuration leaves link audits pending by name.
use crate::identity_link_delivery::LinkAuditReceiver;
use lys_core::Ed25519Identity;
use lys_identity::AgentId;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverConfig {
    service_url: String,
    service_key: String,
    source_agent: String,
    source_issuer: String,
    source_subject: String,
    signing_key_path: PathBuf,
}

fn refused(path: &Path, reason: impl std::fmt::Display) -> ErrorResponse {
    ErrorResponse::new(
        ErrorResponseType::Connection,
        format!(
            "identity_link_audit_not_provisioned: '{}': {reason}",
            path.display()
        ),
    )
}

/// Load only explicitly provisioned trust, never learn the service key from a receipt.
/// The config is JSON; the signing key is an existing raw 32-byte Ed25519 seed.
pub async fn configured_receiver() -> Result<LinkAuditReceiver, ErrorResponse> {
    let path = std::env::var_os("LYS_LINK_AUDIT_CONFIG")
        .map(PathBuf::from)
        .ok_or_else(|| {
            refused(
                Path::new("LYS_LINK_AUDIT_CONFIG"),
                "receiver configuration path is absent",
            )
        })?;
    if !path.is_absolute() {
        return Err(refused(
            &path,
            "LYS_LINK_AUDIT_CONFIG must be an absolute path",
        ));
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|error| refused(&path, error))?;
    let config: ReceiverConfig =
        serde_json::from_slice(&bytes).map_err(|error| refused(&path, error))?;
    let service_key: [u8; 32] = hex::decode(&config.service_key)
        .map_err(|error| refused(&path, format!("service_key: {error}")))?
        .try_into()
        .map_err(|_| refused(&path, "service_key must contain 32 bytes"))?;
    let agent = AgentId::from_str(&config.source_agent).map_err(|error| refused(&path, error))?;
    lys_identity::LoginBinding::new(&config.source_issuer, &config.source_subject)
        .map_err(|error| refused(&path, error))?;
    if !config.signing_key_path.is_absolute() {
        return Err(refused(&path, "signing_key_path must be absolute"));
    }
    let key_path = config.signing_key_path;
    let key = tokio::task::spawn_blocking(move || Ed25519Identity::load(&key_path))
        .await
        .map_err(|error| refused(&path, error))?
        .map_err(|error| refused(&path, error))?;
    let url = reqwest::Url::parse(&config.service_url).map_err(|error| refused(&path, error))?;
    LinkAuditReceiver::new(
        url,
        service_key,
        agent,
        config.source_issuer,
        config.source_subject,
        key,
    )
}
