//! Typed public evidence returned by Lys; none of these fields establishes trust by itself.
use serde::{Deserialize, Serialize};

/// The receipt endpoint's evidence, verified against an independently pinned service key.
#[derive(Clone, Deserialize, Serialize)]
pub struct ReceiverEvidence {
    pub receipt: ReceiptView,
    pub message: String,
    pub checkpoint: CheckpointView,
    pub inclusion_proof: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ReceiptView {
    pub version: u64,
    pub operation: String,
    pub actor: ActorView,
    pub identity: String,
    pub change_kind: u64,
    pub payload_commitment: String,
    pub payload_commitment_hash: String,
    pub log: CoordinateView,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ActorView {
    pub issuer: String,
    pub subject: String,
    pub authenticated_at: u64,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CoordinateView {
    pub index: u64,
    pub tree_size: u64,
    pub root: String,
    pub leaf_hash: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct CheckpointView {
    pub tree_size: u64,
    pub root: String,
}
