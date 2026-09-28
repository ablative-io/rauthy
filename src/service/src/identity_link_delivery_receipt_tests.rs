//! Bound observations require the exact admitted receipt read back from the provisioned service.
use super::http_tests::answer;
use super::*;
use lys_core::merkle::{AppendOnlyTree, RawLeaf, raw_leaf_hash};
use lys_identity::log::Coordinate;
use lys_identity::receipt::Receipt;
use lys_identity::{
    Actor, Change, IdentityEvent, IdentityId, LinkChange, LinkObservation, LoginBinding,
    OperationId, Provenance, sign_event,
};
use serde_json::{Value, json};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn Error>>;

fn evidence(
    observation: &IdentityLinkAudit,
    person: PersonId,
) -> Result<([u8; 32], Value), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let key = Ed25519Identity::load_or_generate(&dir.path().join("service.key"))?;
    let actor = Actor::new(
        LoginBinding::new("https://issuer.test/", "lys-link-audit")?,
        Provenance::by_agent(AgentId::from_bytes([5; 16]), 100),
    );
    let event = IdentityEvent::new(
        OperationId::from_bytes([7; 16]),
        actor,
        IdentityId::Person(person),
        125,
        Change::LinkAudit(LinkObservation::new(
            &observation.id,
            LinkChange::Linked,
            LoginBinding::new(&observation.issuer, &observation.federation_uid)?,
            "https://issuer.test/",
            123,
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
    let receipt = json!({
        "version":receipt.version(), "operation":receipt.operation().to_string(),
        "actor":{"issuer":"https://issuer.test/", "subject":"lys-link-audit", "authenticated_at":100},
        "identity":person.to_string(), "change_kind":receipt.change_kind(),
        "payload_commitment":hex::encode(receipt.payload_commitment()), "payload_commitment_hash":"sha-256",
        "log":{"index":index,"tree_size":tree_size,"root":hex::encode(root),"leaf_hash":hex::encode(receipt.coordinate().leaf_hash)}
    });
    // A later head is legal on readback, but the original receipt never changes.
    tree.append_raw(b"an unrelated later event");
    let (root, tree_size) = tree.root().to_parts();
    let wire = json!({
        "receipt":receipt,"message":hex::encode(signed.bytes()),
        "checkpoint":{"tree_size":tree_size,"root":hex::encode(root)},
        "inclusion_proof":hex::encode(tree.prove_inclusion(index)?.as_bytes())
    });
    Ok((key.public_key_bytes(), wire))
}

// Reading public evidence must use GET on the same configured origin, without
// turning a caller-supplied URL or service key into a new authority.
async fn receipt_answer(listener: &TcpListener, response: &str) -> TestResult {
    let (mut stream, _) = listener.accept().await?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err("receipt reader closed before headers".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let headers = String::from_utf8(bytes)?;
    assert!(
        headers.starts_with("GET /api/receipts/0 HTTP/1.1\r\n"),
        "{headers}"
    );
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn submitted_receipt_is_read_back_verified_and_stable_on_retry() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut receiver = super::tests::receiver(&format!("http://{}/api/", listener.local_addr()?))?;
    let person = PersonId::from_bytes([1; 16]);
    let observation = IdentityLinkAudit {
        id: "original-op".into(),
        user_id: "local-user".into(),
        provider_id: "provider".into(),
        issuer: "https://accounts.test".into(),
        federation_uid: "upstream-user".into(),
        link_change: "linked".into(),
        observed_at: 123,
        observer: Some("https://issuer.test/".into()),
        actor_session: Some("original-session".into()),
        lys_person: Some(person.to_string()),
        receipt: None,
        acknowledged_at: None,
        receipt_verified: false,
    };
    let (key, original) = evidence(&observation, person)?;
    receiver.service_key = key;
    let mut messages = Vec::new();
    for mutation in ["none", "none", "mismatched_readback", "wrong_signature"] {
        let mut returned = original.clone();
        match mutation {
            "mismatched_readback" => returned["receipt"]["operation"] = json!("another-operation"),
            "wrong_signature" => returned["message"] = json!("00"),
            "none" => (),
            _ => return Err("unknown fixture mutation".into()),
        }
        let admitted = json!({"receipt":original["receipt"]}).to_string();
        let returned = returned.to_string();
        let serve = async {
            let request = answer(&listener, "200 OK", &admitted).await?;
            request.verify("/link-audit", &receiver.signing_key.public_key_bytes())?;
            assert_eq!(
                serde_json::from_slice::<Value>(&request.body)?,
                json!({
                    "person":person.to_string(),"source_operation_id":"original-op","change":"linked",
                    "issuer":"https://accounts.test","subject":"upstream-user","observer":"https://issuer.test/","observed_at":123
                })
            );
            receipt_answer(&listener, &returned).await
        };
        let (delivered, served) = tokio::join!(receiver.deliver_bound(&observation, person), serve);
        served?;
        if mutation == "none" {
            let verified = delivered.map_err(|error| error.to_string())?;
            assert_eq!(verified.user(), "local-user");
            assert_eq!(verified.operation(), "original-op");
            messages.push(verified.message().to_owned());
        } else {
            let Err(error) = delivered else {
                return Err("invalid readback was accepted".into());
            };
            assert!(error.message.contains("original-op"), "{error}");
        }
    }
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0], messages[1]);
    let mut unbound = observation.clone();
    unbound.lys_person = None;
    assert!(receiver.deliver_bound(&unbound, person).await.is_err());
    Ok(())
}
