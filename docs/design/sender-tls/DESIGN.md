---
type: design
cluster: sender-tls
title: Provisioned identity audit transport
---

# Provisioned identity audit transport

> **Cluster:** sender-tls

## Intention

An installed sender discloses signed identity observations only to its authenticated receiver.

## Problem

The receipt sender currently accepts loopback HTTP and uses system TLS defaults without the installation CA and SPKI pin; Docker host routing crosses a bridge.

## Solution

Consume the Lys installation contract and use standard certificate verification plus a pre-HTTP SPKI check, preserving immutable retries and verified receipt acknowledgement.

## Principles

- **P1** — Authenticate transport before transmitting signed application data.
- **P2** — A receipt signature and a TLS server identity are independent trust decisions.

## Goals

- The sender consumes the versioned Lys provisioning contract and refuses absent or conflicting trust by name.
- Every request verifies the configured CA chain, hostname and SPKI pin before sending HTTP headers or a body; cleartext and redirects are refused.
- Transport refusals preserve the original operation and durable person binding without acknowledgement or credential disclosure.
- Independent TLS fixtures measure adversarial refusals, including zero HTTP bytes reaching a wrong-pinned peer.
- The installed sender interoperates with the DIRECTORY-055 receiver and preserves identity through retry and upgrade.

## Non-Goals

- Receiver provisioning and TLS issuance — Owned by Lys DIRECTORY-055.
- Checkpoint authentication and login reassignment — Separate protocols remain explicitly unsupported.

## Structure

| Path | Note | Brief |
|------|------|-------|
| `src/service/src/identity_link_tls.rs` | Consume provisioned trust and authenticate the connection before HTTP | SENDERTLS-001 |
| `src/service/src/identity_link_tls_tests.rs` | Consume provisioned trust and authenticate the connection before HTTP | SENDERTLS-001 |
| `src/service/src/identity_link_test_server.rs` | Consume provisioned trust and authenticate the connection before HTTP | SENDERTLS-001 |
| `Cargo.toml` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `Cargo.lock` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/Cargo.toml` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/lib.rs` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/identity_link_delivery.rs` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/identity_link_delivery_config.rs` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/identity_link_delivery_tests.rs` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/identity_link_delivery_http_tests.rs` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/identity_link_delivery_receipt_tests.rs` | Consume provisioned trust and authenticate the connection before HTTP |  |
| `src/service/src/identity_link_tls_adversarial_tests.rs` | Measure handshake refusal before signed data is sent | SENDERTLS-001 |
| `src/service/src/identity_link_install_tests.rs` | Prove the provisioned sender against the real receiver | SENDERTLS-001 |
| `scripts/gates/identity-link-tls.sh` | Prove the provisioned sender against the real receiver | SENDERTLS-001 |
| `docs/identity-link-transport.md` | Prove the provisioned sender against the real receiver | SENDERTLS-001 |
| `.land/identity-link-gate.sh` | Prove the provisioned sender against the real receiver |  |
| `docs/design/project.json` | Prove the provisioned sender against the real receiver |  |
| `.land/identity-link-dependencies.sh` | Prepare and prove the pinned dependencies before the offline round | SENDERTLS-001 |
| `scripts/gates/tests/test_identity_link_dependencies.py` | Prepare and prove the pinned dependencies before the offline round | SENDERTLS-001 |
| `.land/test.sh` | Prepare and prove the pinned dependencies before the offline round |  |

## Inventory

- `Cargo.toml` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `Cargo.lock` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/Cargo.toml` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/src/lib.rs` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/src/identity_link_delivery.rs` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/src/identity_link_delivery_config.rs` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/src/identity_link_delivery_tests.rs` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/src/identity_link_delivery_http_tests.rs` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `src/service/src/identity_link_delivery_receipt_tests.rs` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `.land/identity-link-gate.sh` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.
- `docs/design/project.json` — Existing sender or gate at candidate 1a351ddf; required predecessor landing.

## Constraints

- **CN1** — The source and receipt operations remain immutable and idempotent across cancellation.
- **CN2** — No live-service writes, target-directory changes or cleartext fallback.
