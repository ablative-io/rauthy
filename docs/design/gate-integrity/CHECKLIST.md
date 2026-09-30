# Gate-Integrity — Checklist

## Completed evidence

- [ ] **C1** — A passed verdict names the exact source commit and this invocation and is written only after all required legs succeed.
- [ ] **C2** — A running, interrupted or failed container cannot yield a successful gate result, even when Docker reports ExitCode zero.
- [ ] **C3** — Cancellation preserves non-success and cleans only owned resources; cleanup never hides an earlier failure.
- [ ] **C4** — A real interrupted docker start is refused through the production wrapper, using an event handshake rather than a sleep.
- [ ] **C5** — Missing, malformed, stale and mismatched verdicts are refused and the regression suite participates in the repository gate.
