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
fn exact_signed_observation_verifies_and_has_stable_serialization() -> TestResult {
    let f = fixture()?;
    let first = verify_link_receipt(&f.observation, &f.trust(), &f.evidence)
        .map_err(|error| error.to_string())?;
    let second = verify_link_receipt(&f.observation, &f.trust(), &f.evidence)
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
    assert!(verify_link_receipt(&f.observation, &f.trust(), &wrong_leaf).is_err());
    Ok(())
}

#[test]
fn genuine_receipt_cannot_acknowledge_any_other_observation_field() -> TestResult {
    let f = fixture()?;
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
        assert!(
            verify_link_receipt(&changed, &f.trust(), &f.evidence).is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn wrong_pin_person_or_source_agent_is_refused() -> TestResult {
    let f = fixture()?;
    let mut trust = f.trust();
    trust.service_key = &[9; 32];
    assert!(verify_link_receipt(&f.observation, &trust, &f.evidence).is_err());
    let mut trust = f.trust();
    trust.person = PersonId::from_bytes([2; 16]);
    assert!(verify_link_receipt(&f.observation, &trust, &f.evidence).is_err());
    let mut trust = f.trust();
    trust.source_agent = AgentId::from_bytes([2; 16]);
    assert!(verify_link_receipt(&f.observation, &trust, &f.evidence).is_err());
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
    assert!(verify_link_receipt(&f.observation, &f.trust(), &changed).is_err());
    let mut changed = f.evidence.clone();
    changed.checkpoint.root = hex::encode([9; 32]);
    assert!(verify_link_receipt(&f.observation, &f.trust(), &changed).is_err());
    let mut changed = f.evidence.clone();
    changed.inclusion_proof = "01".into();
    assert!(verify_link_receipt(&f.observation, &f.trust(), &changed).is_err());
    Ok(())
}

#[test]
fn unsigned_receipt_metadata_cannot_disagree_with_signed_event() -> TestResult {
    let f = fixture()?;
    for field in [
        "version",
        "operation",
        "identity",
        "kind",
        "hash",
        "algorithm",
        "actor",
        "index",
        "size",
        "leaf",
        "root",
    ] {
        let mut changed = f.evidence.clone();
        match field {
            "version" => changed.receipt.version += 1,
            "operation" => changed.receipt.operation = "other".into(),
            "identity" => changed.receipt.identity = "other".into(),
            "kind" => changed.receipt.change_kind = 1,
            "hash" => changed.receipt.payload_commitment = hex::encode([9; 32]),
            "algorithm" => changed.receipt.payload_commitment_hash = "other".into(),
            "actor" => changed.receipt.actor.subject = "other".into(),
            "index" => changed.receipt.log.index = 1,
            "size" => changed.receipt.log.tree_size = 2,
            "leaf" => changed.receipt.log.leaf_hash = hex::encode([9; 32]),
            "root" => changed.receipt.log.root = hex::encode([9; 32]),
            _ => return Err("unknown receipt mutation".into()),
        }
        assert!(
            verify_link_receipt(&f.observation, &f.trust(), &changed).is_err(),
            "{field}"
        );
    }
    Ok(())
}
