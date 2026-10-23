# Changelog

All notable changes to this project are documented here.

## 1.1.0 — 2026-10-20

Security and open-source readiness release.

### Fixed

- **Audit chain corruption with `undefined` payload fields.** `undefined` was
  hashed as `null` but dropped by `JSON.stringify`, so the first taint event in
  audit mode (or with `lockdownOnTaint: false`) made the JSONL chain
  unreloadable. Payloads are now pruned before hashing, and a `.head` sidecar
  detects truncated tails.
- **Egress proxy crash on malformed `CONNECT`.** Invalid ports, unbracketed
  IPv6, and malformed authorities now return `400` instead of throwing an
  uncaught `RangeError`. Destination DNS is resolved once and private,
  loopback, link-local, and CGNAT addresses are rejected unless explicitly
  allowed (`egressAllowPrivate`), reducing DNS-rebinding/SSRF risk.
- **Classifier bypasses.** Added Windows `rd /s /q`, `del /f /s /q`,
  `diskpart`, `Clear-Disk`, `Format-Volume`, `rm -rf ~/` / `$HOME/` /
  `${HOME}/`, `production.env`, `.pgpass`, `kubeconfig`, interpreter
  one-liners such as `python -c "open('.env').read()"`, sensitive environment
  reads (`os.environ` / `process.env` + secret-like keys), and `socket.socket`
  network detection.
- **Approval wiring.** SCG now observes DSH's `approval/request` waterfall,
  binds the approved `callId` to an action fingerprint, and writes
  `approval.granted` / `approval.rejected` audit events. Interactive grants
  are deliberately not retained as reusable authorizations. The adapter also
  exposes `approve(sessionId, action)` for programmatic one-shot
  pre-authorization; `permit-approved` grants are consumed exactly once.
- **Fail-open paths.** Corrupt audit logs, failed sandbox lockdown, failed
  egress-proxy startup, and missing shell integration now fail closed for
  monitored actions in enforce mode.
- **Redaction gaps.** Added JSON-style values, `*_TOKEN`/`*_SECRET` keys,
  HTTP Basic credentials, and bare `sk-`/`ghp_`/`github_pat_`/`AKIA` tokens.
- **Egress allowlist ports.** Rules may now pin a port (`api.example.com:443`,
  `[::1]:8080`); a rule without a port keeps the previous any-port behavior.
- **Stale audit sidecar.** E2E and `dsh:verify` now remove `<audit>.head`
  together with the JSONL. A leftover sidecar with a missing JSONL is
  correctly treated as truncation, so resetting only the JSONL made subsequent
  runs fail closed.

### Changed

- Unmonitored tools now emit a `tool.unmonitored` audit event. The default is
  still allow; `unmonitoredTools: 'deny'` opts into deny-by-default.
- Audit claims in the README now describe the hash chain as local integrity,
  not cryptographic tamper-proofing.
- README repositioned around taint-aware session-level downgrade rather than
  a generic agent security runtime.

### Added

- MIT license, changelog, and a tag-driven npm release workflow.
- Windows CI job and a netns job that no longer passes when the probe is
  unavailable.
- `docs/known-gaps.md` (public bypass list) and `SECURITY.md`.
- Regression tests for audit round-trip reload, approval binding, one-shot
  programmatic approvals, and environment-variable taint.

### Breaking / behaviour changes

- Enforce mode can now deny actions when sandbox, audit, or egress isolation is
  unavailable. Operators who explicitly opt out can set `egressProxy: false`,
  `networkIsolation: off`, or `failClosed: false` (not recommended).
- `apply()` now returns `{ approve(sessionId, action, options?) }` for
  programmatic one-shot pre-authorization.
- The tarball path is derived from `package.json` in demo/E2E scripts, so
  version bumps no longer break `pnpm e2e`.
