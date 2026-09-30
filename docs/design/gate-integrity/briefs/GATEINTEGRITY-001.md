---
type: brief
id: GATEINTEGRITY-001
cluster: gate-integrity
title: Refuse interrupted gates without a completed verdict
---

# GATEINTEGRITY-001: Refuse interrupted gates without a completed verdict

> **Cluster:** gate-integrity
> **Depends on:** c3GDi3UzoBF5gOcgvb4UK_x4hW6oNk4HF8I1EfzGav0
> **Blocked by:** The admission card c3GDi3UzoBF5gOcgvb4UK_x4hW6oNk4HF8I1EfzGav0 must land candidate 76a394eb30bca5cbd516d90d110449bd1c57d008 (or a reviewed successor preserving its PostgreSQL gate) on origin/ablative before this brief is built.
> **Checklist:**
> - C1 — A passed verdict names the exact source commit and this invocation and is written only after all required legs succeed.
> - C2 — A running, interrupted or failed container cannot yield a successful gate result, even when Docker reports ExitCode zero.
> - C3 — Cancellation preserves non-success and cleans only owned resources; cleanup never hides an earlier failure.
> - C4 — A real interrupted docker start is refused through the production wrapper, using an event handshake rather than a sleep.
> - C5 — Missing, malformed, stale and mismatched verdicts are refused and the regression suite participates in the repository gate.
> **Stories:**
> - S1 (Operator, Release and gate operation) — As a release operator, I want gate success to prove all required checks finished on this source so that cancellation cannot authorize a release.
> - S2 (Operator, Release and gate operation) — As a gate operator, I want cancellation to retain its outcome and evidence so that safe cleanup cannot be mistaken for passing tests.

## Purpose

Prevent an interrupted Docker gate from authorizing a release with a zero exit code it did not earn. Card BBbN0_sjApDkmVv8WPdmLMi1_6NpTpBjEWWB36TOCQg; Waffles rulings 28 September 20:12 and 20:14 Melbourne.

## Task

Fix the Rauthy repository gate producer and consumer and prove the observed docker-start detach with a real interrupted process. This brief changes gate integrity only; concurrency sizing, application code, Aion implementation and live installation are separate. The depends_on value names the existing external admission card, not an invented brief id. That landing introduces .land/identity-link-gate.sh and the Docker/PostgreSQL wrapper this brief modifies. Do not dispatch against the older host/Hiqlite wrapper.

## Requirements

### R1: Produce and validate an invocation-bound completed verdict

WHEN an identity gate starts, THE SYSTEM SHALL carry a freshly generated invocation identity and exact checked-out Git commit through its producer and consumer. Only after every existing required leg succeeds SHALL the inner gate atomically publish a structured completed verdict to its dedicated invocation-owned result path. THE SYSTEM SHALL NOT infer success from ordinary command output. The consumer SHALL strictly check format, invocation, commit and complete required-leg set; missing, unreadable, malformed, duplicate, stale or mismatched values SHALL return a named nonzero refusal. Keep all current gate legs and commands. Write no passed verdict on signal or failed leg.

**Acceptance:**
- The named unit test supplies a matching completed receipt and receives success; missing, unreadable, truncated, duplicate-member, wrong-invocation, wrong-commit, incomplete-leg and failed-leg receipts each yield a named nonzero refusal. Assert all eight refusal cases execute.
- The producer interrupted before its final atomic publication leaves no acceptable receipt; text in the ordinary log claiming success cannot substitute for that receipt.
- Every normal successful inner-gate path writes exactly one completed receipt after the final test leg; failure of any preceding leg writes no completed receipt.

**Files:**
- create: .land/gate-verdict.py
- create: scripts/gates/tests/test_gate_verdict.py
- modify: .land/identity-link-gate.sh

**Checklist:**
- C1 — A passed verdict names the exact source commit and this invocation and is written only after all required legs succeed.

**Stories:**
- S1 (Operator, Release and gate operation) — As a release operator, I want gate success to prove all required checks finished on this source so that cancellation cannot authorize a release.

### R2: Require a terminal container and preserve cancellation

The production Docker wrapper SHALL treat the attached docker start client as transport, not the gate outcome. AFTER attachment ends, it SHALL inspect the exact owned container and require State.Running=false and State.Status=exited before checking its exit code and R1 verdict. A running, paused, missing or unreadable container SHALL be a named non-success. Signal cancellation SHALL retain a nonzero cancelled outcome, stop and reap owned gate work and clean its container, PostgreSQL container and network. Cleanup failure SHALL turn otherwise-success into failure and SHALL NOT replace an earlier failure with zero. Factor the container supervision into a named helper used both by the real gate and the regression fixture; no production test switch, replacement Docker executable or arbitrary sleep.

**Acceptance:**
- Container-state fixtures prove Running=true with ExitCode=0 is refused before receipt acceptance; exited with nonzero is refused even with a completed receipt; exited zero with matching receipt is accepted.
- The production wrapper handles TERM and INT with named non-success and cleans only the invocation-owned resources; an unrelated container remains running.
- When both gate and cleanup fail, the receipt reports the original gate failure and cleanup failure, and its process result is nonzero.

**Files:**
- create: .land/container-gate.sh
- create: scripts/gates/tests/test_container_outcome.py
- modify: .land/test.sh

**Checklist:**
- C2 — A running, interrupted or failed container cannot yield a successful gate result, even when Docker reports ExitCode zero.
- C3 — Cancellation preserves non-success and cleans only owned resources; cleanup never hides an earlier failure.

**Stories:**
- S1 (Operator, Release and gate operation) — As a release operator, I want gate success to prove all required checks finished on this source so that cancellation cannot authorize a release.
- S2 (Operator, Release and gate operation) — As a gate operator, I want cancellation to retain its outcome and evidence so that safe cleanup cannot be mistaken for passing tests.

### R3: Reproduce the real Docker attachment interruption

A Docker integration regression SHALL execute the R2 production supervision helper against an owned container using small fixture leg commands. Each fixture emits an explicit phase-entered event and blocks on an explicit release signal. After receiving that event, the harness SHALL TERM the real attached docker start client while its container remains running. It SHALL assert named refusal, nonzero outcome, no accepted completed verdict and eventual owned-resource cleanup. This SHALL be measured at the WASM, frontend, Clippy and tests phase boundaries without compiling those heavy legs in the fixture. Also interrupt after final-leg success but before verdict publication. A synthetic log alone SHALL NOT satisfy this test.

**Acceptance:**
- Run scripts/gates/tests/test_gate_interruption.py on Dean with Docker: all four phase cases and the before-publication case execute; each observes the live container before killing the attachment and verifies non-success through the actual production supervision helper.
- A successful control fixture releases all its phases, yields a matching completed receipt and passes; a command failure control is refused.
- The test uses process/pipe/container events to order interruption; it contains no timed sleep or timeout for correctness. It preserves evidence when a control fails and does not stop any unrelated container.

**Files:**
- create: scripts/gates/tests/test_gate_interruption.py
- create: scripts/gates/tests/gate_fixture.sh

**Checklist:**
- C4 — A real interrupted docker start is refused through the production wrapper, using an event handshake rather than a sleep.

**Stories:**
- S1 (Operator, Release and gate operation) — As a release operator, I want gate success to prove all required checks finished on this source so that cancellation cannot authorize a release.
- S2 (Operator, Release and gate operation) — As a gate operator, I want cancellation to retain its outcome and evidence so that safe cleanup cannot be mistaken for passing tests.

### R4: Make verdict regressions part of the repository gate

The repository gate SHALL run the fast receipt/state unit tests and the real Docker interruption regression as declared legs in addition to every existing leg. The regression invokes the lower-level production helper with its fixture and SHALL NOT recursively invoke the complete repository gate. It SHALL fail loudly if Docker or another required test dependency is unavailable. Add operator documentation naming completed, refused and cancelled outcomes and their receipt paths, including the 28 September false-zero incident.

**Acceptance:**
- sh .land/gates.sh runs the new regression entry point exactly once and retains all existing design, format, frontend, Clippy, build and PostgreSQL test checks.
- Removing the completed verdict from an otherwise passing fixture causes this gate leg to exit nonzero; a skipped Docker check cannot return success.
- Run the design gate, shell syntax checks, Python unit tests and full repository gate at the exact implementation commit; report results and retain the interrupted fixture evidence.

**Files:**
- create: scripts/gates/gate-integrity.sh
- create: docs/gate-integrity.md
- modify: .land/gates.sh
- modify: docs/design/project.json

**Checklist:**
- C5 — Missing, malformed, stale and mismatched verdicts are refused and the regression suite participates in the repository gate.

**Stories:**
- S1 (Operator, Release and gate operation) — As a release operator, I want gate success to prove all required checks finished on this source so that cancellation cannot authorize a release.
- S2 (Operator, Release and gate operation) — As a gate operator, I want cancellation to retain its outcome and evidence so that safe cleanup cannot be mistaken for passing tests.

## Boundaries

- SHALL NOT drop existing gate legs, alter Cargo profiles or redirect Cargo target directories.
- SHALL NOT edit application source, live runtime configuration or generic Aion src_gate code. Record any generic consumer defect as a linked follow-up.
- SHALL NOT count a cancelled, unobserved or partially completed execution as green.
- SHALL NOT introduce timers, background recovery workers or a production test-mode switch.

## Verification

- sh scripts/design/gate.sh exits 0.
- sh -n .land/gates.sh .land/test.sh .land/container-gate.sh .land/identity-link-gate.sh scripts/gates/gate-integrity.sh scripts/gates/tests/gate_fixture.sh exits 0.
- python3 -m unittest discover -s scripts/gates/tests -p test_*.py runs all receipt, container and real Docker interruption controls on Dean and exits 0.
- sh .land/gates.sh passes on Dean at the exact implementation commit with a matching completed receipt.
