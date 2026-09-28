//! Adversarial receipt bindings: a genuine service signature cannot acknowledge another act.
use super::*;
use crate::entity::identity_link_receipt_wire::{
    ActorView, CheckpointView, CoordinateView, ReceiptView,
};
use lys_core::Ed25519Identity;
use lys_core::merkle::{AppendOnlyTree, RawLeaf, raw_leaf_hash};
use lys_identity::{
    Actor, IdentityEvent, LinkChange, LinkObservation, LoginBinding, OperationId, Provenance,
    sign_event,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

struct Fixture {
    observation: IdentityLinkAudit,
    key: [u8; 32],
    evidence: ReceiverEvidence,
    tree: AppendOnlyTree<RawLeaf>,
    signer: Ed25519Identity,
}

impl Fixture {
    fn trust(&self) -> ReceiptTrust<'_> {
        ReceiptTrust {
            service_key: &self.key,
            person: PersonId::from_bytes([1; 16]),
            source_agent: AgentId::from_bytes([5; 16]),
            source_issuer: "https://issuer.test",
            source_subject: "lys-link-audit",
        }
    }
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let key = Ed25519Identity::load_or_generate(&dir.path().join("service.key"))?;
    let actor = Actor::new(
        LoginBinding::new("https://issuer.test", "lys-link-audit")?,
        Provenance::by_agent(AgentId::from_bytes([5; 16]), 1_790_000_000),
    );
    let event = IdentityEvent::new(
        OperationId::from_bytes([7; 16]),
        actor,
        IdentityId::Person(PersonId::from_bytes([1; 16])),
        1_790_000_100,
        Change::LinkAudit(LinkObservation::new(
            "source-op-1",
            LinkChange::Linked,
            LoginBinding::new("https://accounts.test", "ada-elsewhere")?,
            "https://issuer.test",
            1_790_000_050,
        )?),
    )?;
    let signed = sign_event(event, &key)?;
    let mut tree = AppendOnlyTree::<RawLeaf>::new();
    let index = tree.append_raw(signed.bytes());
    let (root, tree_size) = tree.root().to_parts();
    let receipt = Receipt::of(
        &signed,
        Coordinate {
            index,
            tree_size,
            root,
            leaf_hash: raw_leaf_hash(signed.bytes()),
        },
    );
    let evidence = ReceiverEvidence {
        message: hex::encode(signed.bytes()),
        receipt: ReceiptView {
            version: receipt.version(),
            operation: receipt.operation().to_string(),
            actor: ActorView {
                issuer: "https://issuer.test".into(),
                subject: "lys-link-audit".into(),
                authenticated_at: 1_790_000_000,
            },
            identity: receipt.identity().to_string(),
            change_kind: 6,
            payload_commitment: hex::encode(receipt.payload_commitment()),
            payload_commitment_hash: "sha-256".into(),
            log: CoordinateView {
                index,
                tree_size,
                root: hex::encode(root),
                leaf_hash: hex::encode(receipt.coordinate().leaf_hash),
            },
        },
        checkpoint: CheckpointView {
            tree_size,
            root: hex::encode(root),
        },
        inclusion_proof: hex::encode(tree.prove_inclusion(index)?.as_bytes()),
    };
    Ok(Fixture {
        key: key.public_key_bytes(),
        signer: key,
        evidence,
        tree,
        observation: IdentityLinkAudit {
            id: "source-op-1".into(),
            user_id: "rauthy-user-not-a-lys-id".into(),
            provider_id: "provider1".into(),
            issuer: "https://accounts.test".into(),
            federation_uid: "ada-elsewhere".into(),
            link_change: "linked".into(),
            observed_at: 1_790_000_050,
            observer: Some("https://issuer.test".into()),
            actor_session: Some("session1".into()),
            lys_person: None,
            receipt: None,
            acknowledged_at: None,
            receipt_verified: false,
        },
    })
}

#[test]
fn exact_signed_observation_canonicalizes_hex_and_json_member_order() -> TestResult {
    let f = fixture()?;
    let first = verify_link_receipt(&f.observation, &f.trust(), &f.evidence)
        .map_err(|error| error.to_string())?;
    let mut upper = f.evidence.clone();
    upper.message.make_ascii_uppercase();
    upper.receipt.payload_commitment.make_ascii_uppercase();
    upper.receipt.log.root.make_ascii_uppercase();
    upper.receipt.log.leaf_hash.make_ascii_uppercase();
    upper.checkpoint.root.make_ascii_uppercase();
    upper.inclusion_proof.make_ascii_uppercase();
    let reordered = format!(
        "{{\"inclusion_proof\":{},\"checkpoint\":{},\"message\":{},\"receipt\":{}}}",
        serde_json::to_string(&upper.inclusion_proof)?,
        serde_json::to_string(&upper.checkpoint)?,
        serde_json::to_string(&upper.message)?,
        serde_json::to_string(&upper.receipt)?,
    );
    let reordered: ReceiverEvidence = serde_json::from_str(&reordered)?;
    let second = verify_link_receipt(&f.observation, &f.trust(), &reordered)
        .map_err(|error| error.to_string())?;
    assert_eq!(first.operation(), f.observation.id);
    assert_eq!(first.user(), f.observation.user_id);
    assert_eq!(first.person(), f.trust().person.to_string());
    assert_eq!(first.evidence(), second.evidence());
    Ok(())
}

#[test]
fn retry_with_later_checkpoint_keeps_the_original_signed_event() -> TestResult {
    let mut f = fixture()?;
    let original = verify_link_receipt(&f.observation, &f.trust(), &f.evidence)
        .map_err(|error| error.to_string())?;
    f.tree.append_raw(b"another admitted event");
    let (root, tree_size) = f.tree.root().to_parts();
    f.evidence.checkpoint = CheckpointView {
        tree_size,
        root: hex::encode(root),
    };
    f.evidence.inclusion_proof = hex::encode(f.tree.prove_inclusion(0)?.as_bytes());
    let retried = verify_link_receipt(&f.observation, &f.trust(), &f.evidence)
        .map_err(|error| error.to_string())?;
    assert_eq!(original.message(), retried.message());
    assert_ne!(original.evidence(), retried.evidence());
    assert_eq!(f.evidence.receipt.log.tree_size, 1);
    assert_eq!(f.evidence.checkpoint.tree_size, 2);
    let mut wrong_leaf = f.evidence.clone();
    wrong_leaf.inclusion_proof = hex::encode(f.tree.prove_inclusion(1)?.as_bytes());
    assert_refused(
        &f.observation,
        &f.trust(),
        &wrong_leaf,
        "ReceiptInvalid: the inclusion proof does not place the leaf in the checkpoint",
    )?;
    Ok(())
}

#[test]
fn genuine_receipt_cannot_acknowledge_any_other_observation_field() -> TestResult {
    let f = fixture()?;
    let mut cases = 0;
    for field in [
        "operation",
        "issuer",
        "subject",
        "change",
        "observer",
        "time",
        "person",
    ] {
        let mut changed = f.observation.clone();
        match field {
            "operation" => changed.id = "another-operation".into(),
            "issuer" => changed.issuer = "https://wrong.test".into(),
            "subject" => changed.federation_uid = "another-subject".into(),
            "change" => changed.link_change = "unlinked".into(),
            "observer" => changed.observer = None,
            "time" => changed.observed_at += 1,
            "person" => changed.lys_person = Some(PersonId::from_bytes([2; 16]).to_string()),
            _ => return Err("unknown fixture mutation".into()),
        }
        let reason = if field == "person" {
            "person does not match the authoritative mapping"
        } else {
            "signed observation differs from the local operation"
        };
        assert_refused(&changed, &f.trust(), &f.evidence, reason)?;
        cases += 1;
    }
    assert_eq!(cases, 7);
    Ok(())
}

#[test]
fn wrong_pin_person_or_source_actor_is_refused() -> TestResult {
    let f = fixture()?;
    let mut trust = f.trust();
    trust.service_key = &[9; 32];
    assert_refused(
        &f.observation,
        &trust,
        &f.evidence,
        "SignerMismatch: the event names a service key other than the one it is verified against",
    )?;
    let mut trust = f.trust();
    trust.person = PersonId::from_bytes([2; 16]);
    assert_refused(
        &f.observation,
        &trust,
        &f.evidence,
        "person does not match the authoritative mapping",
    )?;
    let mut trust = f.trust();
    trust.source_agent = AgentId::from_bytes([2; 16]);
    assert_refused(
        &f.observation,
        &trust,
        &f.evidence,
        "source actor or signing agent does not match",
    )?;
    let mut trust = f.trust();
    trust.source_issuer = "https://wrong.test";
    assert_refused(
        &f.observation,
        &trust,
        &f.evidence,
        "source actor or signing agent does not match",
    )?;
    let mut trust = f.trust();
    trust.source_subject = "wrong-source";
    assert_refused(
        &f.observation,
        &trust,
        &f.evidence,
        "source actor or signing agent does not match",
    )?;
    Ok(())
}

#[test]
fn forged_signature_and_proof_are_refused() -> TestResult {
    let f = fixture()?;
    let mut changed = f.evidence.clone();
    let mut message = hex::decode(&changed.message)?;
    let last = message.last_mut().ok_or("empty fixture message")?;
    *last ^= 1;
    changed.message = hex::encode(message);
    assert_refused(
        &f.observation,
        &f.trust(),
        &changed,
        "SignatureInvalid: the event\'s signature does not verify",
    )?;
    let mut changed = f.evidence.clone();
    changed.checkpoint.root = hex::encode([9; 32]);
    assert_refused(
        &f.observation,
        &f.trust(),
        &changed,
        "receipt metadata differs from its signed event",
    )?;
    Ok(())
}

#[test]
fn unsigned_receipt_metadata_cannot_disagree_with_signed_event() -> TestResult {
    let f = fixture()?;
    let mut cases = 0;
    for field in [
        "version",
        "operation",
        "identity",
        "kind",
        "hash",
        "algorithm",
        "actor",
        "actor_issuer",
        "actor_time",
        "index",
        "size",
        "leaf",
        "root",
    ] {
        let mut changed = f.evidence.clone();
        match field {
            "version" => changed.receipt.version += 1,
            "operation" => changed.receipt.operation = OperationId::from_bytes([8; 16]).to_string(),
            "identity" => changed.receipt.identity = PersonId::from_bytes([8; 16]).to_string(),
            "kind" => changed.receipt.change_kind = 1,
            "hash" => changed.receipt.payload_commitment = hex::encode([9; 32]),
            "algorithm" => changed.receipt.payload_commitment_hash = "other".into(),
            "actor" => changed.receipt.actor.subject = "other".into(),
            "actor_issuer" => changed.receipt.actor.issuer = "https://wrong.test".into(),
            "actor_time" => changed.receipt.actor.authenticated_at += 1,
            "index" => changed.receipt.log.index = 1,
            "size" => changed.receipt.log.tree_size = 2,
            "leaf" => changed.receipt.log.leaf_hash = hex::encode([9; 32]),
            "root" => changed.receipt.log.root = hex::encode([9; 32]),
            _ => return Err("unknown receipt mutation".into()),
        }
        let reason = if field == "leaf" {
            "ReceiptInvalid: the leaf hash is not the message's"
        } else {
            "receipt metadata differs from its signed event"
        };
        assert_refused(&f.observation, &f.trust(), &changed, reason)?;
        cases += 1;
    }
    assert_eq!(cases, 14);
    Ok(())
}

fn assert_refused(
    observation: &IdentityLinkAudit,
    trust: &ReceiptTrust<'_>,
    evidence: &ReceiverEvidence,
    reason: &str,
) -> TestResult {
    let Err(error) = verify_link_receipt(observation, trust, evidence) else {
        return Err(format!("accepted evidence expected to refuse: {reason}").into());
    };
    assert_eq!(
        error.message,
        format!(
            "identity_link_audit_receipt_invalid: operation '{}': {reason}",
            observation.id
        )
    );
    Ok(())
}

#[test]
fn checkpoint_bounds_refuse_by_name() -> TestResult {
    let f = fixture()?;
    let mut cases = 0;
    for (index, size, checkpoint_size) in [(0, 1, 0), (1, 2, 1), (2, 3, 1), (u64::MAX, 1, 1)] {
        let mut changed = f.evidence.clone();
        changed.receipt.log.index = index;
        changed.receipt.log.tree_size = size;
        changed.checkpoint.tree_size = checkpoint_size;
        assert_refused(
            &f.observation,
            &f.trust(),
            &changed,
            "receipt metadata differs from its signed event",
        )?;
        cases += 1;
    }
    assert_eq!(cases, 4);
    Ok(())
}

#[test]
fn inclusion_is_not_authenticated_membership_without_signed_checkpoint() -> TestResult {
    let f = fixture()?;
    let message = hex::decode(&f.evidence.message)?;
    let mut forged_tree = AppendOnlyTree::<RawLeaf>::new();
    forged_tree.append_raw(b"fabricated unsigned history never admitted by the service");
    let index = forged_tree.append_raw(&message);
    let (root, tree_size) = forged_tree.root().to_parts();
    let mut evidence = f.evidence.clone();
    evidence.receipt.log.index = index;
    evidence.receipt.log.tree_size = tree_size;
    evidence.receipt.log.root = hex::encode(root);
    evidence.checkpoint = CheckpointView {
        tree_size,
        root: hex::encode(root),
    };
    evidence.inclusion_proof = hex::encode(forged_tree.prove_inclusion(index)?.as_bytes());
    let accepted =
        verify_link_receipt(&f.observation, &f.trust(), &evidence).map_err(|e| e.to_string())?;
    assert_eq!(accepted.message(), f.evidence.message);
    assert_eq!(evidence.receipt.log.index, 1);
    Ok(())
}

#[test]
fn genuine_other_signed_events_with_true_proofs_cannot_acknowledge_observation() -> TestResult {
    let mut f = fixture()?;
    let changes = [
        (
            Change::LinkAudit(LinkObservation::new(
                "another-source-operation",
                LinkChange::Linked,
                LoginBinding::new("https://accounts.test", "ada-elsewhere")?,
                "https://issuer.test",
                1_790_000_050,
            )?),
            "signed observation differs from the local operation",
        ),
        (
            Change::BindLogin {
                binding: LoginBinding::new("https://other.test", "another-login")?,
            },
            "signed event is not a link observation",
        ),
    ];
    let mut cases = 0;
    for (change, reason) in changes {
        let event = IdentityEvent::new(
            OperationId::from_bytes([8 + cases; 16]),
            Actor::new(
                LoginBinding::new("https://issuer.test", "lys-link-audit")?,
                Provenance::by_agent(AgentId::from_bytes([5; 16]), 1_790_000_000),
            ),
            IdentityId::Person(PersonId::from_bytes([1; 16])),
            1_790_000_101,
            change,
        )?;
        let signed = sign_event(event, &f.signer)?;
        let index = f.tree.append_raw(signed.bytes());
        let (root, tree_size) = f.tree.root().to_parts();
        let coordinate = Coordinate {
            index,
            tree_size,
            root,
            leaf_hash: raw_leaf_hash(signed.bytes()),
        };
        let receipt = Receipt::of(&signed, coordinate);
        let proof = f.tree.prove_inclusion(index)?;
        // Independently prove this is valid evidence for that other event.
        verify_receipt(&receipt, signed.bytes(), &f.key, (tree_size, root), &proof)?;
        let mut evidence = f.evidence.clone();
        evidence.message = hex::encode(signed.bytes());
        evidence.receipt.operation = receipt.operation().to_string();
        evidence.receipt.change_kind = receipt.change_kind();
        evidence.receipt.payload_commitment = hex::encode(receipt.payload_commitment());
        evidence.receipt.log = CoordinateView {
            index,
            tree_size,
            root: hex::encode(root),
            leaf_hash: hex::encode(coordinate.leaf_hash),
        };
        evidence.checkpoint = CheckpointView {
            tree_size,
            root: hex::encode(root),
        };
        evidence.inclusion_proof = hex::encode(proof.as_bytes());
        assert_refused(&f.observation, &f.trust(), &evidence, reason)?;
        cases += 1;
    }
    assert_eq!(cases, 2);
    Ok(())
}
