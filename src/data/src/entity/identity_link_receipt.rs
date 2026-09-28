//! Only signed Lys evidence bound to the exact local observation can acknowledge an audit.
//! The event is authenticated by the pinned service key. Inclusion is checked against
//! the receiver-supplied checkpoint; that checkpoint is not independently signed.
use super::identity_link_audit::IdentityLinkAudit;
pub use super::identity_link_receipt_wire::ReceiverEvidence;
use lys_core::merkle::InclusionProof;
use lys_identity::log::Coordinate;
use lys_identity::receipt::{Receipt, verify_receipt};
use lys_identity::{AgentId, AuthMethod, Change, IdentityId, PersonId, verify_event};
use rauthy_error::{ErrorResponse, ErrorResponseType};

/// Trusted deployment inputs and a person resolved through Lys's authorized lookup.
/// These values must never come from the caller's acknowledgement body.
pub struct ReceiptTrust<'a> {
    pub service_key: &'a [u8; 32],
    pub person: PersonId,
    pub source_agent: AgentId,
    pub source_issuer: &'a str,
    pub source_subject: &'a str,
}

/// A receipt that passed signature, observation and log-inclusion checks.
/// Private members prevent a caller from turning arbitrary text into an acknowledgement.
pub struct VerifiedLinkReceipt {
    operation: String,
    user: String,
    person: String,
    evidence: String,
    message: String,
}

impl VerifiedLinkReceipt {
    /// The canonical signed event, independent of a later inclusion checkpoint.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The immutable source operation this evidence acknowledges.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// The local account whose authoritative Lys mapping was checked.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The verified enduring Lys person, never a Rauthy id or an email guess.
    pub fn person(&self) -> &str {
        &self.person
    }

    /// Canonical JSON field ordering for idempotent storage of this evidence.
    pub fn evidence(&self) -> &str {
        &self.evidence
    }
}

fn refused(operation: &str, reason: impl std::fmt::Display) -> ErrorResponse {
    ErrorResponse::new(
        ErrorResponseType::BadRequest,
        format!("identity_link_audit_receipt_invalid: operation '{operation}': {reason}"),
    )
}

fn hash(operation: &str, field: &str, value: &str) -> Result<[u8; 32], ErrorResponse> {
    let bytes =
        hex::decode(value).map_err(|error| refused(operation, format!("{field}: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| refused(operation, format!("{field} must contain 32 bytes")))
}

/// Verify the receiver's complete evidence before any local acknowledgement write.
///
/// # Errors
/// Refuses an invalid signature, mismatched person/actor/observation/receipt, malformed
/// evidence or an inclusion proof that does not place the signed leaf in the checkpoint.
pub fn verify_link_receipt(
    observation: &IdentityLinkAudit,
    trust: &ReceiptTrust<'_>,
    evidence: &ReceiverEvidence,
) -> Result<VerifiedLinkReceipt, ErrorResponse> {
    let operation = observation.id.as_str();
    let message = hex::decode(&evidence.message)
        .map_err(|error| refused(operation, format!("message: {error}")))?;
    let signed =
        verify_event(&message, trust.service_key).map_err(|error| refused(operation, error))?;
    let event = signed.event();
    if event.identity() != IdentityId::Person(trust.person)
        || observation
            .lys_person
            .as_ref()
            .is_some_and(|person| person != &trust.person.to_string())
    {
        return Err(refused(
            operation,
            "person does not match the authoritative mapping",
        ));
    }
    let actor = event.actor();
    if actor.binding().issuer() != trust.source_issuer
        || actor.binding().subject() != trust.source_subject
        || actor.provenance().method() != AuthMethod::AgentSignature(trust.source_agent)
    {
        return Err(refused(
            operation,
            "source actor or signing agent does not match",
        ));
    }
    let Change::LinkAudit(seen) = event.change() else {
        return Err(refused(operation, "signed event is not a link observation"));
    };
    let change = match seen.change() {
        lys_identity::LinkChange::Linked => "linked",
        lys_identity::LinkChange::Unlinked => "unlinked",
    };
    if seen.source_operation_id() != operation
        || seen.binding().issuer() != observation.issuer
        || seen.binding().subject() != observation.federation_uid
        || Some(seen.observer()) != observation.observer.as_deref()
        || i64::try_from(seen.observed_at()).ok() != Some(observation.observed_at)
        || change != observation.link_change
    {
        return Err(refused(
            operation,
            "signed observation differs from the local operation",
        ));
    }
    let received = &evidence.receipt;
    let coordinate = Coordinate {
        index: received.log.index,
        tree_size: received.log.tree_size,
        root: hash(operation, "receipt.log.root", &received.log.root)?,
        leaf_hash: hash(operation, "receipt.log.leaf_hash", &received.log.leaf_hash)?,
    };
    let expected = Receipt::of(&signed, coordinate);
    if received.version != expected.version()
        || received.operation != expected.operation().to_string()
        || received.identity != expected.identity().to_string()
        || received.change_kind != expected.change_kind()
        || received.payload_commitment_hash != "sha-256"
        || hash(
            operation,
            "payload_commitment",
            &received.payload_commitment,
        )? != expected.payload_commitment()
        || received.actor.issuer != actor.binding().issuer()
        || received.actor.subject != actor.binding().subject()
        || received.actor.authenticated_at != actor.provenance().authenticated_at()
        || coordinate.index.checked_add(1) != Some(coordinate.tree_size)
        || coordinate.tree_size > evidence.checkpoint.tree_size
        || (coordinate.tree_size == evidence.checkpoint.tree_size
            && coordinate.root != hash(operation, "checkpoint.root", &evidence.checkpoint.root)?)
    {
        return Err(refused(
            operation,
            "receipt metadata differs from its signed event",
        ));
    }
    let proof_bytes = hex::decode(&evidence.inclusion_proof)
        .map_err(|error| refused(operation, format!("inclusion_proof: {error}")))?;
    let proof =
        InclusionProof::try_from_bytes(proof_bytes).map_err(|error| refused(operation, error))?;
    verify_receipt(
        &expected,
        &message,
        trust.service_key,
        (
            evidence.checkpoint.tree_size,
            hash(operation, "checkpoint.root", &evidence.checkpoint.root)?,
        ),
        &proof,
    )
    .map_err(|error| refused(operation, error))?;
    let mut normalized = evidence.clone();
    normalized.message = hex::encode(&message);
    normalized.receipt.payload_commitment.make_ascii_lowercase();
    normalized.receipt.log.root.make_ascii_lowercase();
    normalized.receipt.log.leaf_hash.make_ascii_lowercase();
    normalized.checkpoint.root.make_ascii_lowercase();
    normalized.inclusion_proof.make_ascii_lowercase();
    let serialized = serde_json::to_string(&normalized)
        .map_err(|error| refused(operation, format!("evidence serialization: {error}")))?;
    Ok(VerifiedLinkReceipt {
        operation: operation.to_owned(),
        user: observation.user_id.clone(),
        person: trust.person.to_string(),
        evidence: serialized,
        message: hex::encode(message),
    })
}

#[cfg(test)]
#[path = "identity_link_receipt_tests.rs"]
mod tests;
