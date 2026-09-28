//! Request signatures use the receiver's exact domain, unmounted route and unchanged bytes.
use super::*;
use lys_core::attestation::verify_attestation_bytes_by_signer;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

pub(super) fn receiver(url: &str) -> Result<LinkAuditReceiver, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let key = Ed25519Identity::load_or_generate(&dir.path().join("source.key"))?;
    LinkAuditReceiver::new(
        Url::parse(url)?,
        [3; 32],
        AgentId::from_bytes([5; 16]),
        ("https://issuer.test/".into(), "lys-link-audit".into()),
        key,
        NonZeroUsize::new(65_536).ok_or("fixture response limit is zero")?,
    )
    .map_err(|error| error.to_string().into())
}

#[test]
fn receiver_url_refuses_remote_cleartext_and_ambiguous_api_roots() -> TestResult {
    for url in [
        "http://example.com/api/",
        "https://example.com/api",
        "https://user:password@example.com/api/",
        "https://example.com/api/?query=1",
        "https://example.com/api/#fragment",
    ] {
        assert!(receiver(url).is_err(), "{url}");
    }
    receiver("https://identity.example/api/")?;
    receiver("http://127.0.0.1:4010/api/")?;
    Ok(())
}

#[test]
fn signature_covers_exact_body_path_clock_and_nonce_under_lys_domain() -> TestResult {
    let receiver = receiver("https://identity.example/api/")?;
    let nonce = "000102030405060708090a0b0c0d0e0f";
    let header = receiver.signed_header("/link-audit", b"{}", 123, nonce);
    let parts = header.split_ascii_whitespace().collect::<Vec<_>>();
    let [agent, time, seen_nonce, signature] = parts.as_slice() else {
        return Err("signature header must contain four words".into());
    };
    assert_eq!(*agent, "agent-05050505050505050505050505050505");
    assert_eq!(*time, "123");
    assert_eq!(*seen_nonce, nonce);
    let cose = hex::decode(signature)?;
    // SHA-256 of the two literal request bytes, pinned independently of the helper.
    let expected = format!(
        "lys-identity/agent-request/v1\nPOST\n/link-audit\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n123\n{nonce}"
    );
    let key = receiver.signing_key.public_key_bytes();
    verify_attestation_bytes_by_signer(&cose, expected.as_bytes(), &key)?;
    for changed in [
        expected.replace("/link-audit", "/api/link-audit"),
        expected.replace("POST", "GET"),
        expected.replace(
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            &hex::encode(hmac_sha256::Hash::hash(b"{ }")),
        ),
        expected.replace("\n123\n", "\n124\n"),
        expected.replace(nonce, "101112131415161718191a1b1c1d1e1f"),
    ] {
        assert!(verify_attestation_bytes_by_signer(&cose, changed.as_bytes(), &key).is_err());
    }
    Ok(())
}
