//! Sender transport is measured on an owned loopback listener, with no live Lys or database.
use super::*;
use lys_core::attestation::verify_attestation_bytes_by_signer;
use serde_json::{Value, json};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn Error>>;

pub(super) struct Request {
    pub(super) headers: String,
    pub(super) body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Result<&str, Box<dyn Error>> {
        self.headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .ok_or_else(|| format!("missing request header {name}").into())
    }

    pub(super) fn verify(&self, path: &str, key: &[u8; 32]) -> TestResult {
        assert!(
            self.headers
                .starts_with(&format!("POST /api{path} HTTP/1.1\r\n"))
        );
        assert_eq!(self.header("content-type")?, "application/json");
        let words = self
            .header("lys-agent-signature")?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        let [agent, time, nonce, signature] = words.as_slice() else {
            return Err("the signed request header must have four words".into());
        };
        assert_eq!(*agent, "agent-05050505050505050505050505050505");
        assert_eq!(hex::decode(nonce)?.len(), 16);
        assert!(time.parse::<u64>()? > 0);
        let digest = hex::encode(hmac_sha256::Hash::hash(&self.body));
        let payload =
            format!("lys-identity/agent-request/v1\nPOST\n{path}\n{digest}\n{time}\n{nonce}");
        verify_attestation_bytes_by_signer(&hex::decode(signature)?, payload.as_bytes(), key)?;
        Ok(())
    }
}

pub(super) async fn answer(
    listener: &TcpListener,
    status: &str,
    body: &str,
) -> Result<Request, Box<dyn Error>> {
    let (mut stream, _) = listener.accept().await?;
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    let split = loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err("sender closed before its request headers".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(split) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break split + 4;
        }
    };
    let mut request = Request {
        headers: String::from_utf8(bytes[..split].to_vec())?,
        body: bytes[split..].to_vec(),
    };
    let length = request.header("content-length")?.parse::<usize>()?;
    while request.body.len() < length {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err("sender closed before its request body".into());
        }
        request.body.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(request.body.len(), length);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nLocation: /elsewhere\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(request)
}

#[tokio::test]
async fn retry_keeps_exact_request_bytes_but_uses_fresh_signed_nonce() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let receiver = super::tests::receiver(&format!("http://{}/api/", listener.local_addr()?))?;
    let body = json!({"source_operation_id":"original-op", "subject":"unchanged"});
    let key = receiver.signing_key.public_key_bytes();
    let mut nonces = Vec::new();
    for _ in 0..2 {
        let (sent, seen) = tokio::join!(
            receiver.post::<Value>("original-op", "/link-audit", &body),
            answer(&listener, "200 OK", "{\"receipt\":{\"log\":{\"index\":7}}}")
        );
        assert_eq!(
            sent.map_err(|error| error.to_string())?["receipt"]["log"]["index"],
            7
        );
        let seen = seen?;
        seen.verify("/link-audit", &key)?;
        assert_eq!(seen.body, serde_json::to_vec(&body)?);
        let nonce = seen
            .header("lys-agent-signature")?
            .split_ascii_whitespace()
            .nth(2)
            .ok_or("nonce absent")?
            .to_owned();
        nonces.push(nonce);
    }
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
    Ok(())
}

#[tokio::test]
async fn remote_refusal_redirect_and_malformed_success_keep_operation_named() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let receiver = super::tests::receiver(&format!("http://{}/api/", listener.local_addr()?))?;
    let body = json!({"issuer":"https://issuer.test/", "subject":"local-user"});
    for (status, response, reason) in [
        (
            "403 Forbidden",
            "{\"refusal\":\"NotAdmitted\"}",
            "NotAdmitted",
        ),
        ("302 Found", "{}", "HTTP 302"),
        ("200 OK", "not JSON", "decode"),
    ] {
        let (done, finished) = tokio::sync::oneshot::channel();
        let send = async {
            let result = receiver
                .post::<Holder>("original-op", "/link-audit/person", &body)
                .await;
            (result, done.send(()))
        };
        let serve = async {
            let seen = answer(&listener, status, response).await?;
            // Respond even to an erroneous redirect follow, so the regression fails
            // by its actual request rather than leaving a client waiting forever.
            tokio::select! {
                finished = finished => {
                    finished?;
                    Ok::<_, Box<dyn Error>>(seen)
                }
                unexpected = answer(&listener, "403 Forbidden", "unexpected second request") => {
                    unexpected?;
                    Err("sender followed a redirect or issued an unrequested retry".into())
                }
            }
        };
        let ((sent, notified), seen) = tokio::join!(send, serve);
        assert!(notified.is_ok(), "response completion listener disappeared");
        seen?.verify(
            "/link-audit/person",
            &receiver.signing_key.public_key_bytes(),
        )?;
        let Err(error) = sent else {
            return Err("invalid response was accepted".into());
        };
        assert!(error.message.contains("original-op"), "{error}");
        assert!(error.message.contains(reason), "{error}");
    }
    Ok(())
}

#[tokio::test]
async fn person_lookup_uses_original_rauthy_login_not_upstream_provider() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let receiver = super::tests::receiver(&format!("http://{}/api/", listener.local_addr()?))?;
    let observation = IdentityLinkAudit {
        id: "original-op".into(),
        user_id: "local-user".into(),
        provider_id: "google".into(),
        issuer: "https://accounts.google.com".into(),
        federation_uid: "upstream-user".into(),
        link_change: "linked".into(),
        observed_at: 123,
        observer: Some("https://issuer.test/".into()),
        actor_session: Some("original-session".into()),
        lys_person: None,
        receipt: None,
        acknowledged_at: None,
        receipt_verified: false,
    };
    let (sent, seen) = tokio::join!(
        receiver.deliver(&observation),
        answer(&listener, "404 Not Found", "{\"refusal\":\"LoginUnbound\"}")
    );
    let seen = seen?;
    seen.verify(
        "/link-audit/person",
        &receiver.signing_key.public_key_bytes(),
    )?;
    assert_eq!(
        serde_json::from_slice::<Value>(&seen.body)?,
        json!({"issuer":"https://issuer.test/", "subject":"local-user"})
    );
    let Err(error) = sent else {
        return Err("unbound login was accepted".into());
    };
    assert!(error.message.contains("LoginUnbound"), "{error}");
    Ok(())
}
