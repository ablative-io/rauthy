---
type: design
cluster: gate-integrity
title: Gate outcomes that prove completed work
---

# Gate outcomes that prove completed work

> **Cluster:** gate-integrity

## Intention

Only a completed measured gate authorizes release; interruption is never success.

## Problem

On 28 September 2026 an interrupted docker start attachment returned zero while its container was still running. The wrapper read the unfinished container ExitCode zero, cleaned it up, and the outer receipt also said zero although the log stopped at WASM.

## Solution

Carry an invocation and exact commit through a dedicated completed verdict producer and a strict consumer. Container supervision first proves terminal state; it then checks process status and the completed receipt. Cancellation and cleanup retain independent failure evidence. Test the actual detach through the shared production supervision helper.

## Principles

- **P1** — A transport client exit is not a test verdict.
- **P2** — Cleanup cannot turn incomplete work into success.

## Goals

- A passed verdict names the exact source commit and this invocation and is written only after all required legs succeed.
- A running, interrupted or failed container cannot yield a successful gate result, even when Docker reports ExitCode zero.
- Cancellation preserves non-success and cleans only owned resources; cleanup never hides an earlier failure.
- A real interrupted docker start is refused through the production wrapper, using an event handshake rather than a sleep.
- Missing, malformed, stale and mismatched verdicts are refused and the regression suite participates in the repository gate.

## Non-Goals

- VM memory budgets and Cargo job counts — Separate capacity card uses the measured single-job peak.
- Live identity installation — Gate integrity changes neither runtime data nor credentials.

## Structure

| Path | Note | Brief |
|------|------|-------|
| `.land/gate-verdict.py` | Produce and validate an invocation-bound completed verdict | GATEINTEGRITY-001 |
| `scripts/gates/tests/test_gate_verdict.py` | Produce and validate an invocation-bound completed verdict | GATEINTEGRITY-001 |
| `.land/identity-link-gate.sh` | Produce and validate an invocation-bound completed verdict |  |
| `.land/container-gate.sh` | Require a terminal container and preserve cancellation | GATEINTEGRITY-001 |
| `scripts/gates/tests/test_container_outcome.py` | Require a terminal container and preserve cancellation | GATEINTEGRITY-001 |
| `.land/test.sh` | Require a terminal container and preserve cancellation |  |
| `scripts/gates/tests/test_gate_interruption.py` | Reproduce the real Docker attachment interruption | GATEINTEGRITY-001 |
| `scripts/gates/tests/gate_fixture.sh` | Reproduce the real Docker attachment interruption | GATEINTEGRITY-001 |
| `scripts/gates/gate-integrity.sh` | Make verdict regressions part of the repository gate | GATEINTEGRITY-001 |
| `docs/gate-integrity.md` | Make verdict regressions part of the repository gate | GATEINTEGRITY-001 |
| `.land/gates.sh` | Make verdict regressions part of the repository gate |  |
| `docs/design/project.json` | Make verdict regressions part of the repository gate |  |

## Inventory

- `.land/test.sh` — Existing gate boundary in the fork admission candidate 76a394eb.
- `.land/identity-link-gate.sh` — Existing gate boundary in the fork admission candidate 76a394eb.
- `.land/gates.sh` — Existing gate boundary in the fork admission candidate 76a394eb.
- `docs/design/project.json` — Existing gate boundary in the fork admission candidate 76a394eb.

## Constraints

- **CN1** — Use the checkout normal Cargo target directory and retain every existing gate.
- **CN2** — Heavy execution occurs on Dean; the brief does not authorize live mutations.
