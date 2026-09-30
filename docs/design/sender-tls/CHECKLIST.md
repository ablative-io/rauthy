# Sender-Tls — Checklist

## Authenticated transport

- [ ] **C1** — The sender consumes the versioned Lys provisioning contract and refuses absent or conflicting trust by name.
- [ ] **C2** — Every request verifies the configured CA chain, hostname and SPKI pin before sending HTTP headers or a body; cleartext and redirects are refused.
- [ ] **C3** — Transport refusals preserve the original operation and durable person binding without acknowledgement or credential disclosure.
- [ ] **C4** — Independent TLS fixtures measure adversarial refusals, including zero HTTP bytes reaching a wrong-pinned peer.
- [ ] **C5** — The installed sender interoperates with the DIRECTORY-055 receiver and preserves identity through retry and upgrade.
