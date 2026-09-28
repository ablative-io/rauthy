//! Two upstream providers linked to one Rauthy user, against the live test backend.
//!
//! A mock upstream provider runs inside each test on a free local port and plays both Google
//! and GitHub. The authorization code a test hands to the callback names the identity the mock
//! answers for, so every test drives the real provider login, link and callback endpoints.

use crate::common::{get_auth_headers, get_backend_url, get_solved_pow};
use cryptr::utils::secure_random_alnum;
use rauthy_common::constants::CSRF_HEADER;
use rauthy_common::sha256;
use rauthy_common::utils::{base64_url_encode, base64_url_no_pad_encode};
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Client, Response};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod common;

type TestResult = Result<(), Box<dyn Error>>;

const PKCE_VERIFIER: &str = "oDXug9zfYqfz8ejcqMpALRPXfW8QhbKV2AVuScAt8xrLKDAmaRYQ4yRi2uqcH9ys";

/// The identity the mock provider answers for, carried in the authorization code as
/// `subject~email~nonce~mode`. Mode `u` answers through userinfo only, mode `i` also returns an
/// ID token carrying `nonce`.
fn code(subject: &str, email: &str) -> String {
    format!("{subject}~{email}~-~u")
}

fn code_with_id_token(subject: &str, email: &str, nonce: &str) -> String {
    format!("{subject}~{email}~{nonce}~i")
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", secure_random_alnum(12).to_lowercase())
}

/// A minimal upstream provider: `POST /token` and `GET /userinfo`.
async fn start_mock_provider() -> Result<String, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_mock(stream));
        }
    });
    Ok(format!("http://{addr}"))
}

async fn serve_mock(mut stream: TcpStream) {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let (head, body) = loop {
        let Ok(n) = stream.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..pos]).to_string();
        let len = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < pos + 4 + len {
            let Ok(n) = stream.read(&mut chunk).await else {
                return;
            };
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buf[pos + 4..pos + 4 + len]).to_string();
        break (head, body);
    };

    let request_line = head.lines().next().unwrap_or_default();
    let (status, json) = if request_line.starts_with("POST /token") {
        let code = body
            .split('&')
            .find_map(|kv| kv.strip_prefix("code="))
            .map(percent_decode)
            .unwrap_or_default();
        (200, token_response(&code))
    } else if request_line.starts_with("GET /userinfo") {
        let token = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("authorization")
                    .then(|| v.trim().strip_prefix("Bearer ").map(String::from))?
            })
            .unwrap_or_default();
        (200, identity_claims(&token, None))
    } else {
        (404, json!({ "error": "not_found" }))
    };

    let body = json.to_string();
    let res = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
        Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(res.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn token_response(code: &str) -> Value {
    let mut parts = code.split('~');
    let (subject, email, nonce, mode) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let access_token = format!("{subject}~{email}");
    if mode == "i" {
        let header = base64_url_no_pad_encode(br#"{"alg":"RS256"}"#);
        let claims = identity_claims(&access_token, Some(nonce)).to_string();
        let claims = base64_url_no_pad_encode(claims.as_bytes());
        json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "id_token": format!("{header}.{claims}.c2ln"),
        })
    } else {
        json!({ "access_token": access_token, "token_type": "Bearer" })
    }
}

fn identity_claims(access_token: &str, nonce: Option<&str>) -> Value {
    let (subject, email) = access_token.split_once('~').unwrap_or_default();
    let mut claims = json!({
        "sub": subject,
        "email": email,
        "email_verified": true,
        "given_name": "Linked",
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = Value::String(nonce.to_string());
    }
    claims
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Creates an upstream provider pointing at the mock and answers its id.
async fn create_provider(
    mock: &str,
    typ: &str,
    auto_onboarding: bool,
) -> Result<String, Box<dyn Error>> {
    let body = json!({
        "name": unique(&format!("Link {typ} ")),
        "typ": typ,
        "enabled": true,
        "issuer": format!("{mock}/{typ}"),
        "authorization_endpoint": format!("{mock}/authorize"),
        "token_endpoint": format!("{mock}/token"),
        "userinfo_endpoint": format!("{mock}/userinfo"),
        "use_pkce": true,
        "client_secret_basic": false,
        "client_secret_post": false,
        "auto_onboarding": auto_onboarding,
        "auto_link": false,
        "client_id": "mock-client",
        "scope": "openid email",
    });
    let res = Client::new()
        .post(format!("{}/providers/create", get_backend_url()))
        .headers(get_auth_headers().await?)
        .json(&body)
        .send()
        .await?;
    let res = expect_status(res, 200).await?;
    let provider = res.json::<Value>().await?;
    Ok(provider["id"].as_str().ok_or("provider id")?.to_string())
}

async fn delete_provider(id: &str) -> TestResult {
    let res = Client::new()
        .delete(format!("{}/providers/{id}", get_backend_url()))
        .headers(get_auth_headers().await?)
        .send()
        .await?;
    expect_status(res, 200).await?;
    Ok(())
}

async fn delete_user(id: &str) -> TestResult {
    let res = Client::new()
        .delete(format!("{}/users/{id}", get_backend_url()))
        .headers(get_auth_headers().await?)
        .send()
        .await?;
    expect_status(res, 204).await?;
    Ok(())
}

async fn expect_status(res: Response, status: u16) -> Result<Response, Box<dyn Error>> {
    if res.status().as_u16() != status {
        let got = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(format!("expected HTTP {status}, got {got}: {text}").into());
    }
    Ok(res)
}

/// Answers the error body after checking the status, for a named refusal.
async fn expect_refusal(res: Response, status: u16, name: &str) -> TestResult {
    let got = res.status().as_u16();
    let text = res.text().await?;
    assert_eq!(got, status, "refusal {name}: {text}");
    assert!(text.contains(name), "refusal names {name}: {text}");
    Ok(())
}

/// One browser: its cookies and its session's CSRF token.
struct Browser {
    client: Client,
    cookies: BTreeMap<String, String>,
    csrf: String,
    last_sign_in: Option<(String, String)>,
}

/// What a started provider login hands the browser for the callback.
struct Started {
    state: String,
    xsrf_token: String,
    location: String,
}

impl Browser {
    async fn new() -> Result<Self, Box<dyn Error>> {
        let mut slf = Self {
            client: Client::new(),
            cookies: BTreeMap::new(),
            csrf: String::new(),
            last_sign_in: None,
        };
        let res = slf
            .client
            .post(format!("{}/oidc/session", get_backend_url()))
            .send()
            .await?;
        slf.take_cookies(&res);
        let info = expect_status(res, 201).await?.json::<Value>().await?;
        slf.csrf = info["csrf_token"].as_str().ok_or("csrf token")?.to_string();
        Ok(slf)
    }

    fn take_cookies(&mut self, res: &Response) {
        for value in res.headers().get_all(header::SET_COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            let pair = value.split(';').next().unwrap_or_default();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_string(), value.to_string());
            }
        }
    }

    fn headers(&self) -> Result<HeaderMap, Box<dyn Error>> {
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&cookie)?);
        headers.insert(CSRF_HEADER, HeaderValue::from_str(&self.csrf)?);
        Ok(headers)
    }

    fn login_body(provider_id: &str) -> Value {
        let backend = get_backend_url();
        json!({
            "client_id": "rauthy",
            "redirect_uri": format!("{backend}/oidc/callback"),
            "code_challenge": base64_url_encode(sha256!(PKCE_VERIFIER.as_bytes())),
            "code_challenge_method": "S256",
            "provider_id": provider_id,
            "pkce_challenge": base64_url_encode(sha256!(PKCE_VERIFIER.as_bytes())),
        })
    }

    async fn started(&mut self, res: Response) -> Result<Started, Box<dyn Error>> {
        self.take_cookies(&res);
        let res = expect_status(res, 202).await?;
        let location = res
            .headers()
            .get(header::LOCATION)
            .ok_or("location")?
            .to_str()?
            .to_string();
        let state = query_param(&location, "state").ok_or("state")?;
        let xsrf_token = res.text().await?;
        Ok(Started {
            state,
            xsrf_token,
            location,
        })
    }

    /// Starts a sign-in through `provider_id`.
    async fn start_login(&mut self, provider_id: &str) -> Result<Started, Box<dyn Error>> {
        let mut body = Self::login_body(provider_id);
        body["pow"] = Value::String(get_solved_pow().await);
        let res = self
            .client
            .post(format!("{}/providers/login", get_backend_url()))
            .headers(self.headers()?)
            .json(&body)
            .send()
            .await?;
        self.started(res).await
    }

    /// Starts linking `provider_id` to the signed-in account.
    async fn start_link(&mut self, provider_id: &str) -> Result<Started, Box<dyn Error>> {
        let res = self.post_link(provider_id).await?;
        self.started(res).await
    }

    async fn post_link(&mut self, provider_id: &str) -> Result<Response, Box<dyn Error>> {
        let prepared = self
            .client
            .post(format!(
                "{}/providers/{provider_id}/link/prepare",
                get_backend_url()
            ))
            .headers(self.headers()?)
            .send()
            .await?;
        if !prepared.status().is_success() {
            return Ok(prepared);
        }
        let intent: Value = expect_status(prepared, 201).await?.json().await?;
        let (source, code) = self
            .last_sign_in
            .clone()
            .ok_or("signed-in credential missing")?;
        self.sign_in(&source, &code).await?;
        let mut body = Self::login_body(provider_id);
        body["pow"] = Value::String(get_solved_pow().await);
        body["intent_id"] = intent["intent_id"].clone();
        Ok(self
            .client
            .post(format!(
                "{}/providers/{provider_id}/link",
                get_backend_url()
            ))
            .headers(self.headers()?)
            .json(&body)
            .send()
            .await?)
    }

    async fn callback(
        &mut self,
        started: &Started,
        code: &str,
    ) -> Result<Response, Box<dyn Error>> {
        let code = if code.ends_with("~u") {
            if let Some(nonce) = query_param(&started.location, "nonce") {
                let mut identity = code.split('~');
                code_with_id_token(
                    identity.next().ok_or("subject")?,
                    identity.next().ok_or("email")?,
                    &nonce,
                )
            } else {
                code.to_string()
            }
        } else {
            code.to_string()
        };
        self.callback_with(&started.state, &started.xsrf_token, &code)
            .await
    }

    async fn callback_with(
        &mut self,
        state: &str,
        xsrf_token: &str,
        code: &str,
    ) -> Result<Response, Box<dyn Error>> {
        let res = self
            .client
            .post(format!("{}/providers/callback", get_backend_url()))
            .headers(self.headers()?)
            .json(&json!({
                "state": state,
                "code": code,
                "xsrf_token": xsrf_token,
                "pkce_verifier": PKCE_VERIFIER,
            }))
            .send()
            .await?;
        self.take_cookies(&res);
        Ok(res)
    }

    /// Signs in through `provider_id` as the identity `code` names, and answers the user id.
    async fn sign_in(&mut self, provider_id: &str, code: &str) -> Result<String, Box<dyn Error>> {
        let started = self.start_login(provider_id).await?;
        let res = self.callback(&started, code).await?;
        // 205 is a sign-in that asks the user to complete their values
        if res.status().as_u16() != 205 {
            expect_status(res, 202).await?;
        }
        self.last_sign_in = Some((provider_id.to_string(), code.to_string()));
        self.user_id().await
    }

    /// Links `provider_id` to the signed-in account as the identity `code` names.
    async fn link(&mut self, provider_id: &str, code: &str) -> TestResult {
        let started = self.start_link(provider_id).await?;
        let res = self.callback(&started, code).await?;
        expect_status(res, 204).await?;
        Ok(())
    }

    async fn user_id(&self) -> Result<String, Box<dyn Error>> {
        let res = self
            .client
            .get(format!("{}/oidc/sessioninfo", get_backend_url()))
            .headers(self.headers()?)
            .send()
            .await?;
        let info = expect_status(res, 200).await?.json::<Value>().await?;
        Ok(info["user_id"].as_str().ok_or("user id")?.to_string())
    }

    async fn links(&self) -> Result<Vec<Value>, Box<dyn Error>> {
        let res = self
            .client
            .get(format!("{}/providers/links", get_backend_url()))
            .headers(self.headers()?)
            .send()
            .await?;
        Ok(expect_status(res, 200).await?.json::<Vec<Value>>().await?)
    }

    async fn unlink(&self, provider_id: &str) -> Result<Response, Box<dyn Error>> {
        let links = self.links().await?;
        let link = links
            .iter()
            .find(|link| link["provider_id"] == provider_id)
            .ok_or("link absent")?;
        let request = json!({"operation_id": unique("unlink-"), "provider_id":provider_id,"subject":link["federation_uid"]});
        Ok(self
            .client
            .delete(format!(
                "{}/providers/{provider_id}/link",
                get_backend_url()
            ))
            .headers(self.headers()?)
            .json(&request)
            .send()
            .await?)
    }
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

async fn user(id: &str) -> Result<Value, Box<dyn Error>> {
    let res = Client::new()
        .get(format!("{}/users/{id}", get_backend_url()))
        .headers(get_auth_headers().await?)
        .send()
        .await?;
    Ok(expect_status(res, 200).await?.json::<Value>().await?)
}

async fn admin_links(user_id: &str) -> Result<Vec<Value>, Box<dyn Error>> {
    let res = Client::new()
        .get(format!(
            "{}/providers/links/users/{user_id}",
            get_backend_url()
        ))
        .headers(get_auth_headers().await?)
        .send()
        .await?;
    Ok(expect_status(res, 200).await?.json::<Vec<Value>>().await?)
}

async fn pending_audit(user_id: &str) -> Result<Vec<Value>, Box<dyn Error>> {
    let res = Client::new()
        .get(format!("{}/providers/links/audit", get_backend_url()))
        .headers(get_auth_headers().await?)
        .send()
        .await?;
    let all = expect_status(res, 200).await?.json::<Vec<Value>>().await?;
    Ok(all
        .into_iter()
        .filter(|a| a["user_id"] == user_id)
        .collect())
}

async fn ack(id: &str, receipt: &str) -> Result<Response, Box<dyn Error>> {
    Ok(Client::new()
        .post(format!(
            "{}/providers/links/audit/{id}/ack",
            get_backend_url()
        ))
        .headers(get_auth_headers().await?)
        .json(&json!({ "receipt": receipt }))
        .send()
        .await?)
}

fn provider_ids(links: &[Value]) -> Vec<String> {
    links
        .iter()
        .map(|l| l["provider_id"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Signs in through `first`, links `second` under another email, then signs in through each in
/// fresh sessions and finds the same unchanged user every time.
async fn link_pair(first_typ: &str, second_typ: &str) -> TestResult {
    let mock = start_mock_provider().await?;
    let first = create_provider(&mock, first_typ, true).await?;
    let second = create_provider(&mock, second_typ, false).await?;
    let first_email = format!("{}@first.test", unique("pair"));
    let first_code = code(&unique("sub-"), &first_email);
    let second_code = code(&unique("sub-"), &format!("{}@second.test", unique("pair")));

    let mut browser = Browser::new().await?;
    let user_id = browser.sign_in(&first, &first_code).await?;
    browser.link(&second, &second_code).await?;

    let links = browser.links().await?;
    assert_eq!(provider_ids(&links), vec![first.clone(), second.clone()]);
    assert_eq!(links[0]["primary"], true);
    assert_eq!(links[1]["primary"], false);
    assert_eq!(
        provider_ids(&admin_links(&user_id).await?),
        provider_ids(&links)
    );

    let through_second = Browser::new().await?.sign_in(&second, &second_code).await?;
    assert_eq!(
        through_second, user_id,
        "the second provider signs in the same user"
    );
    let through_first = Browser::new().await?.sign_in(&first, &first_code).await?;
    assert_eq!(
        through_first, user_id,
        "the first provider still signs in the same user"
    );

    let stored = user(&user_id).await?;
    assert_eq!(stored["id"], user_id.as_str(), "the user id never changes");
    assert_eq!(
        stored["email"],
        first_email.as_str(),
        "a sign-in through the second provider leaves the email alone"
    );
    assert_eq!(stored["auth_provider_id"], first.as_str());

    delete_user(&user_id).await?;
    delete_provider(&first).await?;
    delete_provider(&second).await?;
    Ok(())
}

/// ID001_LINK_PAIR: Google then GitHub resolve to one unchanged user.
#[tokio::test]
async fn id001_link_pair_google_then_github() -> TestResult {
    println!("ID001_LINK_PAIR");
    link_pair("google", "github").await
}

/// ID001_LINK_PAIR: GitHub then Google resolve to one unchanged user.
#[tokio::test]
async fn id001_link_pair_github_then_google() -> TestResult {
    println!("ID001_LINK_PAIR");
    link_pair("github", "google").await
}

/// ID001_LINK_REFUSAL: an identity with the same email as a user, but another subject, is not
/// merged into that user, and an identity another user owns is not linked again.
#[tokio::test]
async fn id001_link_refusal_collisions() -> TestResult {
    println!("ID001_LINK_REFUSAL");
    let mock = start_mock_provider().await?;
    let google = create_provider(&mock, "google", true).await?;
    let github = create_provider(&mock, "github", true).await?;
    let email = format!("{}@collide.test", unique("c"));
    let owned_code = code(&unique("sub-"), &email);

    let mut owner = Browser::new().await?;
    let owner_id = owner.sign_in(&google, &owned_code).await?;

    // same email, different subject
    let mut stranger = Browser::new().await?;
    let started = stranger.start_login(&google).await?;
    let res = stranger
        .callback(&started, &code(&unique("sub-"), &email))
        .await?;
    expect_refusal(res, 403, "already exists but is not linked").await?;

    // an identity another user owns
    let mut other = Browser::new().await?;
    let other_id = other
        .sign_in(
            &github,
            &code(&unique("sub-"), &format!("{}@other.test", unique("o"))),
        )
        .await?;
    let started = other.start_link(&google).await?;
    let res = other.callback(&started, &owned_code).await?;
    expect_refusal(res, 403, "identity_link_taken").await?;

    assert_eq!(provider_ids(&owner.links().await?), vec![google.clone()]);
    assert_eq!(provider_ids(&other.links().await?), vec![github.clone()]);

    delete_user(&owner_id).await?;
    delete_user(&other_id).await?;
    delete_provider(&google).await?;
    delete_provider(&github).await?;
    Ok(())
}

/// ID001_LINK_REFUSAL: a used link intent is not replayed, an intent is not completed in
/// another account's session, and a wrong CSRF token, state or nonce links nothing.
#[tokio::test]
async fn id001_link_refusal_intents() -> TestResult {
    println!("ID001_LINK_REFUSAL");
    let mock = start_mock_provider().await?;
    let google = create_provider(&mock, "google", true).await?;
    let github = create_provider(&mock, "github", false).await?;

    let mut alice = Browser::new().await?;
    let alice_id = alice
        .sign_in(
            &google,
            &code(&unique("sub-"), &format!("{}@a.test", unique("a"))),
        )
        .await?;
    let mut bob = Browser::new().await?;
    let bob_id = bob
        .sign_in(
            &google,
            &code(&unique("sub-"), &format!("{}@b.test", unique("b"))),
        )
        .await?;

    // CSRF token mismatch
    let started = alice.start_link(&github).await?;
    let res = alice
        .callback_with(
            &started.state,
            "WrongXsrfToken",
            &code(&unique("s"), "x@x.test"),
        )
        .await?;
    expect_refusal(res, 401, "invalid CSRF token").await?;

    // state mismatch
    let started = alice.start_link(&github).await?;
    let res = alice
        .callback_with(
            "WrongState",
            &started.xsrf_token,
            &code(&unique("s"), "x@x.test"),
        )
        .await?;
    expect_refusal(res, 400, "`state` does not match").await?;

    // an ID token issued for another nonce
    let started = alice.start_link(&github).await?;
    assert!(
        query_param(&started.location, "nonce").is_some(),
        "a link sends its nonce upstream"
    );
    let res = alice
        .callback(
            &started,
            &code_with_id_token(&unique("s"), "x@x.test", "NotTheLinkNonce"),
        )
        .await?;
    expect_refusal(res, 403, "identity_link_nonce_mismatch").await?;

    // another account's session completing alice's intent
    let started = alice.start_link(&github).await?;
    let alice_callback = alice
        .cookies
        .iter()
        .filter(|(k, _)| k.contains("UpstreamAuthCallback"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<Vec<_>>();
    for (k, v) in alice_callback {
        bob.cookies.insert(k, v);
    }
    let res = bob
        .callback(&started, &code(&unique("s"), "x@x.test"))
        .await?;
    expect_refusal(res, 403, "identity_link_intent_mismatch").await?;

    // an ID token for the link's own nonce links, and the used intent is not replayed
    let started = alice.start_link(&github).await?;
    let callback_cookies = alice.cookies.clone();
    let nonce = query_param(&started.location, "nonce").ok_or("nonce")?;
    let github_code =
        code_with_id_token(&unique("sub-"), &format!("{}@gh.test", unique("a")), &nonce);
    let res = alice.callback(&started, &github_code).await?;
    expect_status(res, 204).await?;
    alice.cookies = callback_cookies;
    let res = alice.callback(&started, &github_code).await?;
    assert!(
        !res.status().is_success(),
        "a used link intent is refused: {}",
        res.status()
    );

    assert_eq!(
        provider_ids(&alice.links().await?),
        vec![google.clone(), github.clone()],
        "only the one completed link was made"
    );
    assert_eq!(provider_ids(&bob.links().await?), vec![google.clone()]);

    // starting a link for a provider already linked
    let res = alice.post_link(&github).await?;
    expect_refusal(res, 400, "identity_link_provider_linked").await?;

    delete_user(&alice_id).await?;
    delete_user(&bob_id).await?;
    delete_provider(&google).await?;
    delete_provider(&github).await?;
    Ok(())
}

/// ID001_LINK_REFUSAL: the last way to sign in is never unlinked.
#[tokio::test]
async fn id001_link_refusal_final_unlink() -> TestResult {
    println!("ID001_LINK_REFUSAL");
    let mock = start_mock_provider().await?;
    let google = create_provider(&mock, "google", true).await?;
    let github = create_provider(&mock, "github", false).await?;

    let mut browser = Browser::new().await?;
    let user_id = browser
        .sign_in(
            &google,
            &code(&unique("sub-"), &format!("{}@u.test", unique("u"))),
        )
        .await?;

    let res = browser.unlink(&google).await?;
    expect_refusal(res, 400, "identity_link_last_method").await?;
    let res = browser
        .client
        .delete(format!("{}/providers/link", get_backend_url()))
        .headers(browser.headers()?)
        .send()
        .await?;
    expect_status(res, 400).await?;
    assert_eq!(provider_ids(&browser.links().await?), vec![google.clone()]);

    browser
        .link(
            &github,
            &code(&unique("sub-"), &format!("{}@u2.test", unique("u"))),
        )
        .await?;
    let res = browser
        .client
        .delete(format!("{}/providers/link", get_backend_url()))
        .headers(browser.headers()?)
        .send()
        .await?;
    expect_status(res, 400).await?;

    let res = browser.unlink(&google).await?;
    expect_status(res, 200).await?;
    let links = browser.links().await?;
    assert_eq!(provider_ids(&links), vec![github.clone()]);
    assert_eq!(
        links[0]["primary"], true,
        "the remaining link becomes primary"
    );
    assert_eq!(user(&user_id).await?["auth_provider_id"], github.as_str());

    let res = browser.unlink(&github).await?;
    expect_refusal(res, 400, "identity_link_last_method").await?;
    assert_eq!(provider_ids(&browser.links().await?), vec![github.clone()]);

    delete_user(&user_id).await?;
    delete_provider(&google).await?;
    delete_provider(&github).await?;
    Ok(())
}

/// ID001_LINK_AUDIT: every link and unlink leaves one pending observation with a stable id,
/// committed with the change; only the receiver's receipt acknowledges it, a redelivered
/// acknowledgement changes nothing, and an unacknowledged observation stays visible.
#[tokio::test]
async fn id001_link_audit_outbox() -> TestResult {
    println!("ID001_LINK_AUDIT");
    let mock = start_mock_provider().await?;
    let google = create_provider(&mock, "google", true).await?;
    let github = create_provider(&mock, "github", false).await?;
    let google_subject = unique("sub-");

    let mut browser = Browser::new().await?;
    let user_id = browser
        .sign_in(
            &google,
            &code(&google_subject, &format!("{}@audit.test", unique("a"))),
        )
        .await?;
    browser
        .link(
            &github,
            &code(&unique("sub-"), &format!("{}@audit2.test", unique("a"))),
        )
        .await?;

    // the change is committed and its observation waits, however often it is read
    let pending = pending_audit(&user_id).await?;
    assert_eq!(pending.len(), 2, "one observation per link: {pending:?}");
    let again = pending_audit(&user_id).await?;
    let ids = |v: &[Value]| {
        v.iter()
            .map(|a| {
                a["source_operation_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&pending), ids(&again), "each observation keeps its id");
    let by_provider = |v: &[Value], provider: &str| {
        v.iter()
            .find(|a| a["provider_id"] == provider)
            .cloned()
            .ok_or_else(|| format!("no observation for {provider}: {v:?}"))
    };
    let first = by_provider(&pending, google.as_str())?;
    assert_eq!(first["change"], "linked");
    assert_eq!(first["provider_id"], google.as_str());
    assert_eq!(first["subject"], google_subject.as_str());
    assert_eq!(first["state"], "pending");
    assert!(first["receipt"].is_null());
    for link in browser.links().await? {
        assert_eq!(link["audit"], "pending", "no link reads as audited yet");
    }

    // Arbitrary administrator text is not a receiver acknowledgement.
    let first_id = first["source_operation_id"].as_str().ok_or("id")?;
    expect_status(ack(first_id, "receipt-one").await?, 400).await?;
    let missing_config = Client::new()
        .post(format!(
            "{}/providers/links/audit/{first_id}/ack",
            get_backend_url()
        ))
        .headers(get_auth_headers().await?)
        .json(&json!({}))
        .send()
        .await?;
    assert!(missing_config.status().is_server_error());
    let body = missing_config.text().await?;
    assert!(
        body.contains("identity_link_audit_not_provisioned"),
        "{body}"
    );
    let pending = pending_audit(&user_id).await?;
    assert_eq!(pending.len(), 2);
    for link in browser.links().await? {
        assert_eq!(link["audit"], "pending");
    }

    // an unlink is observed too
    expect_status(browser.unlink(&google).await?, 200).await?;
    let pending = pending_audit(&user_id).await?;
    assert_eq!(pending.len(), 3);
    let unlinked = pending
        .iter()
        .find(|row| row["provider_id"] == google.as_str() && row["change"] == "unlinked")
        .ok_or("missing unlink observation")?;
    assert_eq!(unlinked["change"], "unlinked");
    assert_eq!(unlinked["subject"], google_subject.as_str());

    // only an administrator or an API key reads and acknowledges observations
    let res = browser
        .client
        .get(format!("{}/providers/links/audit", get_backend_url()))
        .headers(browser.headers()?)
        .send()
        .await?;
    assert!(res.status().is_client_error(), "a user session is refused");

    delete_user(&user_id).await?;
    delete_provider(&google).await?;
    delete_provider(&github).await?;
    Ok(())
}
