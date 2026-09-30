# Explicit provider links for one Rauthy person

Owner: Chippy. Reviewer: Waffles. Card: c3GDi3UzoBF5gOcgvb4UK_x4hW6oNk4HF8I1EfzGav0.
Integration base: ablative 4d20bd322546b2e7c0e21b95c0ed1c5e2a0f4aef on v0.36.2.
28 September 17:23 ruling e4cd56dc: preserve existing 32/V31 migrations byte-for-byte,
add forward V32 (PostgreSQL only), preserve UNIQUE(user,provider) and primary ordering.
Design: Lys DIRECTORY-004 and IDENTITY-001 revision 5, row 03.

Waffles' ruling, 28 September 2026, 16:31 Melbourne, message
7578a09d14d5a2dcb1ceddc04a9529a5f968d18df20e2e368d9d7a8854e0ec08:
use the development exception; number migrations after this base, then renumber
at the release-tag rebase. No real-user deployment before that release rebase.
Linking is explicit and authenticated. The older email-auto-link card words are
superseded. An email match never grants a link, even when both emails are verified.

## Requirements and order

1. Preserve authoritative lookup errors; refuse collisions and mismatched route,
   provider, session and person. A failed lookup never means a new account.
   Remove the automatic-email-link path and refuse requests to enable it.
2. Add `V32__identity_link_admission.sql` only. Waffles superseded the dual-store
   ruling at 17:41 on 28 September: Lys ships PostgreSQL; Hiqlite is cache only.
   Retain the applied 32/V31 identity-link migrations unchanged. Migrate every existing pair transactionally into a
   relation unique on provider and subject, preserving user IDs. Half-pairs,
   duplicate owners and absent references refuse migration rather than drop rows.
   Add durable intents and an audit outbox. Historical backfill is identified as
   migration, not falsely represented as a newly observed linking ceremony.
3. An intent names the authenticated person, session, selected provider, callback,
   nonce, expiry and fresh reauthentication evidence. It is single-use under the
   same transaction that admits the link. Cancellation or concurrent callbacks
   cannot admit a second link. Existing password/passkey security requirements
   remain; provider-only users must have a complete reauthentication path too.
4. Read all logins from the relation, including either-provider sign-in. Update
   user/provider deletion, account-type derivation, import/export and UI readers.
   Unlink is provider-specific and refuses removal of the final usable method.
   Link/unlink and audit provenance commit together. A durable mutation with an
   outstanding audit is visibly pending, never reported as fully acknowledged.
5. Deliver stable source operation IDs to DIRECTORY-003's actual served contract.
   Resolve exact issuer/subject to Lys PersonId through its authorised path;
   never equate Rauthy IDs and Lys IDs or infer either from email. Verify that the
   receipt acknowledges the exact event. Retries retain the original operation.
6. Account UI lists all links, provides explicit link/unlink and reauthentication,
   and shows pending/refused/acknowledged outcomes in the existing visual language.

## File wall

The DIRECTORY-004 R1 fork paths remain in scope. Additional named modules needed
to keep the implementation bounded: `src/data/src/entity/identity_link_store.rs`,
`identity_link_intents.rs`, `identity_link_audit.rs`, `identity_link_unlink.rs`, `identity_link_sql.rs`,
`identity_link_admission.rs`, `identity_link_observation.rs`,
and tests under `src/data/tests/identity_links*.rs`.
Additional integration seams: `src/data/src/migration/db_migrate.rs` (both transfer
directions), `src/data/src/api_cookie.rs` (typed malformed-cookie refusal),
`src/bin/src/server.rs` and `src/api/src/openapi.rs` (route registration),
`src/service/src/oidc/authorize.rs` and `src/data/src/entity/webauthn.rs`
(record actual reauthentication, never a silent session refresh),
`frontend/src/utils/helpers.ts` (request fresh sign-in),
`frontend/src/lib/account/AccInfo.svelte` (existing link control),
`frontend/src/lib/account/AccLinkedProviders.svelte` (all linked identities),
`frontend/src/api/types/auth_provider.ts` (the served account response types), and
`frontend/src/lib/admin/providers/ProviderConfig.svelte` (remove auto-link control).
`src/data/src/migration/identity_links.rs`, `identity_link_format.rs` and
`mod.rs` own cross-database transfer and named format checks;
`src/data/src/database.rs` calls the format check before migrations.
`.land/gates.sh`, `.land/test.sh` and `.land/identity-link-gate.sh` declare the
isolated PostgreSQL Docker gate using the venue's existing upstream builder image.
Cargo uses the checkout's normal target directory; the venue removes the checkout
after the run. No target override or seat-specific cache is permitted.
Further required seams must be named in this brief before editing them.

## Acceptance and evidence

- ID001_LINK_PAIR: both provider orders, unchanged user subject, sign-out and
  sign-in through either, then reopen; exercise the real PostgreSQL identity datastore.
- ID001_LINK_REFUSAL: same email/different subject, already-owned identity,
  unauthenticated, stale/cross-account/replayed intent, nonce/CSRF mismatch and
  final-method unlink. Each refusal names its cause and leaves no unintended link.
- ID001_LINK_MIGRATION: PostgreSQL V31 to V32; pre/post IDs and all links match;
  interrupted transaction and retry; malformed legacy pairs refuse atomically;
  schema version incompatibility refuses by name.
- ID001_LINK_AUDIT: database commit before response or acknowledgement, restart,
  retry, exact receipt validation and one logical Lys event. Audit outage remains
  visible and pending. A reused operation ID with different evidence refuses.
- Run the upstream WASM/UI preparation, Rust formatting/Clippy/tests, frontend
  formatting/type checks, and PostgreSQL transaction cases on Dean. Record exact
  command, commit, result and omitted checks. Source-only tests are not live proof.

Source publication on the fork main line `ablative` is permitted for exact-commit
verification; a published source commit is not a release. No production install,
pin update or completion claim until the exact fork commit passes the agreed full gate and review.
Current source and this brief are work in progress, not an accepted gate receipt.

## Gate correction, 28 September 17:42 Melbourne

The former fork test leg booted Hiqlite by default. Waffles requires an isolated
PostgreSQL 17 container with HIQLITE=false for the backend and transaction tests.
No Hiqlite forward migration or SQLite transaction test is part of this delivery.
The existing 32/V31 migrations remain byte-for-byte unchanged. The new fork
refuses Hiqlite as its identity datastore by name at startup.

The receiver's agent/person binding and service-key pin are not provisioned on
any installation. Archie confirmed this at 17:42; Waffles owns the provisioning
brief after PR96. Pending audit is not claimed delivered while that is absent.

## Receipt verification seam, 28 September 18:49 Melbourne
The receipt consumer additionally owns Cargo.toml, Cargo.lock, src/data/Cargo.toml,
src/data/src/entity/mod.rs, identity_link_receipt.rs, identity_link_receipt_wire.rs,
and identity_link_receipt_tests.rs beside the existing audit module. Reuse the
Lys verifier at the exact PR96 revision while its landing is pending; replace
that pin with the landed revision before delivery. Verify the pinned service
signature, exact local observation, authoritative person mapping, configured
source actor/agent, receipt fields and Merkle inclusion before acknowledging.
Caller-supplied receipt text alone is never sufficient.

The delivery seam also owns src/service/Cargo.toml, src/service/src/lib.rs and
src/service/src/identity_link_delivery.rs. It signs exact serialized request
bytes, performs authorized person lookup, redelivers one stable operation,
fetches evidence from the configured service and only then verifies it.

Acknowledgement integration additionally owns src/service/src/identity_link_delivery_config.rs,
src/api/src/auth_providers.rs, src/api_types/src/auth_providers.rs and the existing
src/bin/tests/zzh_identity_links.rs acceptance test. LYS_LINK_AUDIT_CONFIG names
a provisioned JSON file containing service_url (API root, trailing slash), service_key
(pinned public Ed25519 key, hex), source_agent, source_issuer, source_subject and
absolute signing_key_path, and response_body_bytes (a required positive byte limit).
The same limit bounds success and refusal response bodies, including chunked responses;
oversized responses refuse by operation, HTTP status and configured limit, without
copying their body into the refusal. No secret or identity is generated on delivery.
The acknowledgement POST accepts an empty object and asks the configured receiver
to deliver/verify; caller-written receipt strings are refused. Missing configuration
returns identity_link_audit_not_provisioned and leaves the observation pending.
The authoritative person mapping is persisted before remote submission.

V33__verified_link_receipts.sql advances the identity-link format to 2.
Legacy printable receipts stay stored but become pending until verified; the
receipt_verified marker is written only alongside a verified acknowledgement.
Receipt state readers, transfer code and format checks preserve this distinction.
This seam also owns identity_links.rs, migration/identity_links.rs,
migration/identity_link_format.rs, frontend/src/api/types/auth_provider.ts, and
src/data/tests/identity_links_admission.rs for migration acceptance.

Sender contract tests live in src/service/src/identity_link_delivery_tests.rs.
The consumer pins the landed Lys receiver at e813d65a95b71421ca2404f90315fddd9e6490f2.
HTTP transport fixtures live in src/service/src/identity_link_delivery_http_tests.rs; they run only on an owned loopback listener and never contact a deployed service.
Signed receipt delivery cases and their receiver-owned event fixture live in src/service/src/identity_link_delivery_receipt_tests.rs. This fixture tests the HTTP submission and proof readback after durable mapping; database admission remains separately covered by the PostgreSQL gate.

Review boundary: the landed receiver's checkpoint is not signed independently. The
event signature is verified under the pinned service key; inclusion is checked
relative to the receiver's own checkpoint. Archie owns the signed-checkpoint follow-up.
A changed directory person mapping is a named pending refusal retaining the original
binding. No supported reassignment protocol is known; never reset the binding or
claim repeated delivery will repair it.

Waffles ruling d8d20c80: installation provisions the sender through the directory,
writes private files itself, mounts them read-only and configures install-authority
TLS on a container-reachable address. No manual file placement or cleartext exception.
This is a follow-on card reviewed with Archie, not part of the current admission gate.
The current sender's loopback HTTP constructor allowance must be removed there before
production installation, with TLS transport fixtures replacing cleartext fixtures.
