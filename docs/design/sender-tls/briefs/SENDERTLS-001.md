---
type: brief
id: SENDERTLS-001
cluster: sender-tls
title: Authenticate the provisioned identity audit receiver before sending
---

# SENDERTLS-001: Authenticate the provisioned identity audit receiver before sending

> **Cluster:** sender-tls
> **Depends on:** DIRECTORY-055
> **Blocked by:** The sender receipt implementation represented by candidate 1a351ddf32d3c55b1cf2f97d4da1e1102b75bcf5 (including 38a5d0e4) must land on origin/ablative before this brief builds., DIRECTORY-055 must land in https://github.com/ablative-io/lys.git. Pin and record its exact landed revision, which provides the shared configuration, TLS receiver and provisioning fixture; do not guess a future commit., After the exact Lys dependency revision and lockfile are resolved, the lead/venue prepares that revision and every locked registry dependency in each actual gate execution Cargo home before an offline round; record an offline metadata proof. Source publication alone does not satisfy this prerequisite.
> **Checklist:**
> - C1 — The sender consumes the versioned Lys provisioning contract and refuses absent or conflicting trust by name.
> - C2 — Every request verifies the configured CA chain, hostname and SPKI pin before sending HTTP headers or a body; cleartext and redirects are refused.
> - C3 — Transport refusals preserve the original operation and durable person binding without acknowledgement or credential disclosure.
> - C4 — Independent TLS fixtures measure adversarial refusals, including zero HTTP bytes reaching a wrong-pinned peer.
> - C5 — The installed sender interoperates with the DIRECTORY-055 receiver and preserves identity through retry and upgrade.
> **Stories:**
> - S1 (Installation owner, Operate identity without handling credentials) — As an installation owner, I want the installed sender to authenticate my receiver without manual key copying so that my identity observations remain private.
> - S2 (Installation owner, Operate identity without handling credentials) — As an operator, I want a failed delivery to remain pending with a named cause so that retry preserves the original identity and audit operation.

## Purpose

Complete authenticated transport for the installed identity audit sender, under Waffles 28 September 2026 20:27 Melbourne no-cleartext ruling.

## Task

This repository owns only the Rauthy sender. Lys provisioning and receiver TLS are DIRECTORY-055. origin/ablative is integration main; origin/main is upstream and must never be written.

## Requirements

### R1: Consume provisioned trust and authenticate the connection before HTTP

Consume the shared versioned sender configuration introduced by DIRECTORY-055; pin both Lys crate dependencies to its landed commit (or a later reviewed descendant containing that contract), with Cargo.lock updated, and do not hand-mirror its schema. Require service_url, service_key, source_agent, source_issuer, source_subject, signing_key_path, tls_ca_path, tls_server_spki_sha256 and positive response_body_bytes. Preserve the schema version semantics of that shared type. Validate paths and material by name; the sender loads only its own Ed25519 seed and public trust. Require HTTPS for every address, including loopback; retain the existing refusal of URL credentials, query, fragment and a missing API-root trailing slash. Remove the loopback HTTP exception. Use a named TLS client module with standard chain, validity, hostname and handshake-signature verification AND the configured SHA-256 SPKI pin. Compare the pin during certificate authentication before any HTTP request headers or body can be transmitted; inspecting the response certificate afterwards is forbidden. Use the provisioned CA trust, not automatic trust discovery or a received receipt as a trust source. The receipt-signing public key and TLS SPKI pin remain distinct. Redirects remain disabled for person lookup, delivery and receipt readback; bound every response by the declared positive response_body_bytes. Session reuse or resumption must never bypass the initial authenticated configuration or retain a session across a changed trust configuration. Preserve the original operation, signed observation and durable person binding; no transport failure acknowledges a record. Split named modules to retain the LOC gate. Update existing delivery fixtures to TLS in this row so the existing tests remain buildable and retain their assertions. Offline dependency preparation is explicit: after pinning the landed Lys revision and updating Cargo.lock, run cargo fetch --locked from that exact manifest in a network-enabled venue preparation step, into the same ordinary Cargo home used by the worker. Then run cargo metadata --locked --offline against it. Record the manifest commit, lockfile digest, resolved Lys Git commit, platform and Cargo-home location. A host cache alone does not satisfy the Docker gate: prepare the same owned builder container before its measured offline gate starts, keeping its normal Cargo home and checkout target. Add .land/identity-link-dependencies.sh with separate prepare and verify operations, and make .land/test.sh require its verify result before invoking the measured gate with Cargo offline. The connected preparation is not a gate pass; no dependency miss may enable network during measured legs, change the target directory, fetch latest main or fall back to a different revision. The card runner likewise needs this preparation before its first offline measurement; if unavailable, name the missing cache prerequisite and stop before the round, not report unmeasured checks as passed.

**Acceptance:**
- Load a fixture generated by the shared DIRECTORY-055 configuration type; compare every typed member, schema version and both different public pins. Missing or zero response policy, unknown version, missing seed, unreadable CA and malformed SPKI pin each refuse by field/path without a network request. Assert these six cases execute.
- Observe a valid HTTPS request at a fixture with the configured CA, SAN and SPKI, then repeat on its reused connection. Assert existing immutable operation, nonce freshness and durable person-binding semantics still hold.
- Exercise explicit http://localhost, http://127.0.0.1 and http://[::1] API roots. Each is refused before opening a transport; no loopback exception remains.
- Run all existing identity-link delivery and receipt tests after converting their fixture transport to TLS; keep every existing refusal and no-ack assertion.
- On Dean, a preparation receipt resolves the exact pinned Lys commit in the actual worker Cargo home; cargo metadata --locked --offline succeeds with network unavailable. In an isolated cold-cache fixture it refuses the missing Git revision by name. The Docker builder repeats the verify check in its own context before measurement; a warm host cache cannot stand in for that check.

**Files:**
- create: src/service/src/identity_link_tls.rs
- create: src/service/src/identity_link_tls_tests.rs
- create: src/service/src/identity_link_test_server.rs
- create: .land/identity-link-dependencies.sh
- create: scripts/gates/tests/test_identity_link_dependencies.py
- modify: Cargo.toml
- modify: Cargo.lock
- modify: src/service/Cargo.toml
- modify: src/service/src/lib.rs
- modify: src/service/src/identity_link_delivery.rs
- modify: src/service/src/identity_link_delivery_config.rs
- modify: src/service/src/identity_link_delivery_tests.rs
- modify: src/service/src/identity_link_delivery_http_tests.rs
- modify: src/service/src/identity_link_delivery_receipt_tests.rs
- modify: .land/test.sh

**Checklist:**
- C1 — The sender consumes the versioned Lys provisioning contract and refuses absent or conflicting trust by name.
- C2 — Every request verifies the configured CA chain, hostname and SPKI pin before sending HTTP headers or a body; cleartext and redirects are refused.
- C3 — Transport refusals preserve the original operation and durable person binding without acknowledgement or credential disclosure.

**Stories:**
- S1 (Installation owner, Operate identity without handling credentials) — As an installation owner, I want the installed sender to authenticate my receiver without manual key copying so that my identity observations remain private.
- S2 (Installation owner, Operate identity without handling credentials) — As an operator, I want a failed delivery to remain pending with a named cause so that retry preserves the original identity and audit operation.

### R2: Measure handshake refusal before signed data is sent

Build independent TLS peer fixtures from explicitly distinct certificate authorities, hostnames, server keys and receipt keys. Standard TLS verification remains active alongside pinning; a custom verifier must delegate all certificate and TLS handshake-signature checks to the standard verifier and add pin verification, never replace those checks with a pin-only decision. Measure peer-side HTTP parsing/received application bytes, not merely a client error. For failed handshakes, await the peer connection task terminal result before asserting no HTTP headers/body were received; no sleep, timer or frame count. Test a valid chain and hostname with the wrong SPKI separately from wrong CA and wrong hostname, so each refusal has one cause. Configure fixtures with supported signature algorithms and normal TLS operation. Use explicit event handshakes for connection and cancellation. No insecure verifier or test-mode branch in production. TLS transcripts may contain public handshake data; the no-disclosure assertion concerns HTTP application data, including lys-agent-signature and the observation body. Count all cases and compare named refusal classes/stages, not is_err alone. All failure outcomes retain pending local work.

**Acceptance:**
- Execute separate wrong-CA, wrong-hostname, wrong-SPKI, expired-certificate and invalid-handshake-signature cases. Each reaches its intended verification check, returns its named refusal and the joined peer task reports zero HTTP application bytes. Assert all five cases execute; a valid control receives the expected request.
- For a valid TLS peer returning a redirect, assert the redirect target received zero requests and the original operation stays pending. For unauthorized-agent and over-limit responses assert named refusal, the configured bound and no acknowledgement. Assert these three cases execute.
- Cancel at the explicit connected-before-send boundary and after receiver commit but before receipt readback. Reopen local storage and retry the same operation. The former submits no observation; the latter uses receiver idempotence and verifies one original audit admission. Neither creates a new operation id.
- A changed receipt key under the correct TLS key fails receipt verification; a changed TLS key under the correct receipt key fails before HTTP. These two controls prove the trust pins are not interchangeable.

**Files:**
- create: src/service/src/identity_link_tls_adversarial_tests.rs
- modify: src/service/src/lib.rs
- modify: src/service/src/identity_link_tls_tests.rs
- modify: src/service/src/identity_link_test_server.rs
- modify: src/service/src/identity_link_delivery_receipt_tests.rs
- modify: src/service/Cargo.toml

**Checklist:**
- C2 — Every request verifies the configured CA chain, hostname and SPKI pin before sending HTTP headers or a body; cleartext and redirects are refused.
- C3 — Transport refusals preserve the original operation and durable person binding without acknowledgement or credential disclosure.
- C4 — Independent TLS fixtures measure adversarial refusals, including zero HTTP bytes reaching a wrong-pinned peer.

**Stories:**
- S1 (Installation owner, Operate identity without handling credentials) — As an installation owner, I want the installed sender to authenticate my receiver without manual key copying so that my identity observations remain private.
- S2 (Installation owner, Operate identity without handling credentials) — As an operator, I want a failed delivery to remain pending with a named cause so that retry preserves the original identity and audit operation.

### R3: Prove the provisioned sender against the real receiver

Add an isolated acceptance entry point that launches the DIRECTORY-055 receiver and the actual Rauthy sender using provisioned scratch files and an isolated PostgreSQL fixture. Invoke the supported delivery path, not an alternate test client. Receiver artifacts must be from the exact pinned Lys revision and their source identity recorded. Never write to a real directory or live identity service. Prove signed observation, original-person resolution, verified receipt, local acknowledgement and retry idempotence over TLS, from the sender container through the declared host/bridge route. Keep the original source issuer/subject and the existing lys-link-audit source login. Use generated install-service files; never provision production secrets by hand. Test absence of configuration as a named pending condition. Declare this acceptance in the repository gate with its tools and fixture prerequisites, fail when a prerequisite is unavailable and use the ordinary checkout target directory. Document public configuration and named pending outcomes without seed bytes. Unsigned checkpoints prove inclusion relative to the returned root, not independently authenticated log membership; retain this explicit limitation. Original-login reassignment remains unsupported and refuses mapping conflicts. Coordinate production activation with the matched DIRECTORY-055 receiver and generated configuration; neither repository source landing alone is an installation receipt. Verify the release manifest pins compatible artifacts before install replaces configuration.

**Acceptance:**
- From a scratch provisioned installation, deliver through the actual sender to the real receiver, verify the receipt and acknowledge locally. Retry the original operation after an interrupted readback and count exactly one audit admission with the original responsible person.
- Read sender identity, seed and generated configuration before and after the supported install-service upgrade/rollback fixture from DIRECTORY-055; bytes remain unchanged and an original pending operation is deliverable.
- Run the repository gate on Dean at the exact implementation commit, with the new isolated transport acceptance as a required leg. Capture completed test counts and source revisions; no missing Docker/receiver artifact or skipped acceptance may pass.

**Files:**
- create: src/service/src/identity_link_install_tests.rs
- create: scripts/gates/identity-link-tls.sh
- create: docs/identity-link-transport.md
- modify: src/service/src/lib.rs
- modify: src/service/Cargo.toml
- modify: .land/identity-link-gate.sh
- modify: docs/design/project.json

**Checklist:**
- C5 — The installed sender interoperates with the DIRECTORY-055 receiver and preserves identity through retry and upgrade.

**Stories:**
- S1 (Installation owner, Operate identity without handling credentials) — As an installation owner, I want the installed sender to authenticate my receiver without manual key copying so that my identity observations remain private.
- S2 (Installation owner, Operate identity without handling credentials) — As an operator, I want a failed delivery to remain pending with a named cause so that retry preserves the original identity and audit operation.

## Boundaries

- SHALL NOT modify the Lys repository, implement its installer launcher or hand-provision live keys.
- SHALL NOT permit cleartext for loopback, disable standard certificate verification, learn trust from a peer or send signed HTTP data before pin verification.
- SHALL NOT change signed historical formats, implement login reassignment, claim authenticated checkpoint membership or weaken receipt verification.
- SHALL NOT change Cargo target directories, omit existing gates, introduce silent defaults, timers or background delivery tasks.

## Verification

- sh scripts/design/gate.sh exits 0.
- The full repository gate on Dean passes at the exact implementation commit, including existing receipt tests, adversarial TLS cases and the new real-receiver acceptance.
- Report each tested source revision, all executed adversarial counts and any unrun venue matrix leg; an unrun required leg blocks landing.
