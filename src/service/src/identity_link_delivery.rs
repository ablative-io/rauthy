//! Explicit audit delivery uses the original observation and verifies Lys before acknowledgement.
use lys_core::Ed25519Identity;
use lys_core::attestation::sign_attestation;
use lys_identity::{AgentId, PersonId};
use rauthy_data::entity::identity_link_audit::IdentityLinkAudit;
use rauthy_data::entity::identity_link_receipt::{
    ReceiptTrust, ReceiverEvidence, VerifiedLinkReceipt, verify_link_receipt,
};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Provisioned receiver inputs; never supplied in an acknowledgement request.
pub struct LinkAuditReceiver {
    client: Client,
    base: Url,
    service_key: [u8; 32],
    source_agent: AgentId,
    source_issuer: String,
    source_subject: String,
    signing_key: Ed25519Identity,
}

#[derive(Deserialize)]
struct Holder {
    person: String,
}

#[derive(Deserialize)]
struct Delivered {
    receipt: serde_json::Value,
}

fn refused(operation: &str, stage: &str, reason: impl std::fmt::Display) -> ErrorResponse {
    ErrorResponse::new(
        ErrorResponseType::Connection,
        format!("identity_link_audit_pending: operation '{operation}', {stage}: {reason}"),
    )
}

impl LinkAuditReceiver {
    /// Construct from validated provisioning, never fetch a replacement trust key at delivery.
    /// The URL names the service's API root, including its `/api/` mount prefix.
    pub fn new(
        base: Url,
        service_key: [u8; 32],
        source_agent: AgentId,
        source_issuer: String,
        source_subject: String,
        signing_key: Ed25519Identity,
    ) -> Result<Self, ErrorResponse> {
        let loopback = base.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if (base.scheme() != "https" && !(base.scheme() == "http" && loopback))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.path().ends_with('/')
        {
            return Err(refused(
                "configuration",
                "service_url",
                "require HTTPS (or loopback HTTP), no credentials/query/fragment, and a trailing slash",
            ));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| refused("configuration", "http client", error))?;
        Ok(Self {
            client,
            base,
            service_key,
            source_agent,
            source_issuer,
            source_subject,
            signing_key,
        })
    }

    /// Deliver or redeliver the same immutable observation and verify the resulting event.
    /// Any failure leaves local acknowledgement untouched. Cancellation may leave a remote
    /// admission; retry always uses the same source operation so Lys can answer that admission.
    pub async fn deliver(
        &self,
        observation: &IdentityLinkAudit,
    ) -> Result<VerifiedLinkReceipt, ErrorResponse> {
        let operation = observation.id.as_str();
        let observer = observation.observer.as_deref().ok_or_else(|| {
            refused(
                operation,
                "provenance",
                "original observer is absent; do not invent one",
            )
        })?;
        let holder: Holder = self
            .post(
                operation,
                "/link-audit/person",
                &serde_json::json!({"issuer": observer, "subject": observation.user_id}),
            )
            .await?;
        let person = PersonId::from_str(&holder.person)
            .map_err(|error| refused(operation, "person lookup", error))?;
        if observation
            .lys_person
            .as_ref()
            .is_some_and(|saved| saved != &holder.person)
        {
            return Err(refused(
                operation,
                "person lookup",
                "mapping changed after it was bound",
            ));
        }
        let observation =
            IdentityLinkAudit::bind_person(operation, &observation.user_id, &holder.person).await?;
        self.deliver_bound(&observation, person).await
    }

    // The durable binding separates account resolution from submission. No request is
    // sent for an unbound observation, including retries after a changed directory lookup.
    async fn deliver_bound(
        &self,
        observation: &IdentityLinkAudit,
        person: PersonId,
    ) -> Result<VerifiedLinkReceipt, ErrorResponse> {
        let operation = observation.id.as_str();
        let bound_person = person.to_string();
        if observation.lys_person.as_deref() != Some(bound_person.as_str()) {
            return Err(refused(
                operation,
                "person binding",
                "observation is not durably bound to this person",
            ));
        }
        let observer = observation.observer.as_deref().ok_or_else(|| {
            refused(
                operation,
                "provenance",
                "original observer is absent; do not invent one",
            )
        })?;
        let observed_at = u64::try_from(observation.observed_at)
            .map_err(|error| refused(operation, "observed_at", error))?;
        let delivered: Delivered = self
            .post(
                operation,
                "/link-audit",
                &serde_json::json!({
                    "person": bound_person,
                    "source_operation_id": observation.id,
                    "change": observation.link_change,
                    "issuer": observation.issuer,
                    "subject": observation.federation_uid,
                    "observer": observer,
                    "observed_at": observed_at,
                }),
            )
            .await?;
        let index = delivered
            .receipt
            .pointer("/log/index")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| refused(operation, "delivery receipt", "missing unsigned log.index"))?;
        let url = self
            .base
            .join(&format!("receipts/{index}"))
            .map_err(|error| refused(operation, "receipt URL", error))?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| refused(operation, "read receipt", error))?;
        let evidence: ReceiverEvidence =
            Self::read_response(operation, "read receipt", response).await?;
        if serde_json::to_value(&evidence.receipt)
            .map_err(|error| refused(operation, "compare receipt", error))?
            != delivered.receipt
        {
            return Err(refused(
                operation,
                "receipt readback",
                "readback differs from admitted receipt",
            ));
        }
        verify_link_receipt(
            observation,
            &ReceiptTrust {
                service_key: &self.service_key,
                person,
                source_agent: self.source_agent,
                source_issuer: &self.source_issuer,
                source_subject: &self.source_subject,
            },
            &evidence,
        )
    }

    fn signed_header(&self, path: &str, bytes: &[u8], signed_at: u64, nonce: &str) -> String {
        let digest = hmac_sha256::Hash::hash(bytes);
        let payload = format!(
            "lys-identity/agent-request/v1\nPOST\n{path}\n{}\n{signed_at}\n{nonce}",
            hex::encode(digest)
        );
        let cose = sign_attestation(payload.as_bytes(), &self.signing_key).to_cose_bytes();
        format!(
            "{} {signed_at} {nonce} {}",
            self.source_agent,
            hex::encode(cose)
        )
    }

    async fn read_response<T: serde::de::DeserializeOwned>(
        operation: &str,
        stage: &str,
        response: reqwest::Response,
    ) -> Result<T, ErrorResponse> {
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.map_err(|error| {
                refused(
                    operation,
                    stage,
                    format!("HTTP {status}; unreadable refusal: {error}"),
                )
            })?;
            return Err(refused(operation, stage, format!("HTTP {status}: {body}")));
        }
        response
            .json()
            .await
            .map_err(|error| refused(operation, stage, format!("invalid JSON response: {error}")))
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        operation: &str,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, ErrorResponse> {
        let bytes = serde_json::to_vec(body)
            .map_err(|error| refused(operation, "encode request", error))?;
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| refused(operation, "signing clock", error))?;
        let signed_at = u64::try_from(time.as_millis())
            .map_err(|error| refused(operation, "signing clock", error))?;
        let nonce = lys_identity::OperationId::generate()
            .map_err(|error| refused(operation, "nonce", error))?;
        let nonce = hex::encode(nonce.as_bytes());
        let header = self.signed_header(path, &bytes, signed_at, &nonce);
        let url = self
            .base
            .join(path.trim_start_matches('/'))
            .map_err(|error| refused(operation, "request URL", error))?;
        let response = self
            .client
            .post(url)
            .header("lys-agent-signature", header)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes)
            .send()
            .await
            .map_err(|error| refused(operation, path, error))?;
        Self::read_response(operation, path, response).await
    }
}

#[cfg(test)]
#[path = "identity_link_delivery_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "identity_link_delivery_http_tests.rs"]
mod http_tests;

#[cfg(test)]
#[path = "identity_link_delivery_receipt_tests.rs"]
mod receipt_tests;
