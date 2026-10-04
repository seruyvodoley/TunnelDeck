# TunnelDeck Architecture

## Server component topology

```text
TunnelDeck.app
   ├─ sudo -n -u tunneldeck-agent → tunneldeck-agent (read-only telemetry)
   ├─ tunneldeck-helper 1.2.1      stable legacy operations
   └─ tunneldeck-helper2 2.0       new transactional remediation
```

`HelperService` talks only to the legacy path. `Helper2Service`, owned by `RemediationController`, talks only to the side-by-side protocol-2 path. Their capabilities and response models are separate, so a missing Helper 2 cannot disable established 1.2.1 behavior.

## Wake and server telemetry flow

Local SQLite is the macOS operational source of truth. Sleep stops the single polling coordinator without recording an outage. Wake reloads local history, attempts an incremental Agent 2.0 cursor sync, reloads merged history, refreshes the selected node, and restarts exactly one polling loop.

The server boundary is split: `tunneldeck-agent` collects read-only facts as an unprivileged systemd timer, while `tunneldeck-helper` performs only explicit transactional writes. `AgentSyncController` owns catch-up import rather than expanding `AppViewModel` again.

## Persistence ownership

- Persist: nodes, monitoring samples/events, peer and AdGuard telemetry, alert rules/runtime state, configuration baselines, and Agent sync cursors. Credentials and private keys never enter SQLite.
- Rebuild: incidents from persisted events; baseline drift from the saved baseline plus a fresh observation; Fleet summaries from per-node last-known samples; charts from persisted telemetry.
- Refresh after wake: system, WireGuard, service, helper, AdGuard, security, exposure, and current Fleet state. Until refreshed, prior observations are stale—not offline.
- Session-only: in-flight progress, presented errors, raw command results, and helper reachability. Security/exposure facts are deliberately reacquired because old evidence cannot prove current reachability.

## 2.0 direction

`AppViewModel` remains the compatibility facade for 1.x screens. New behavior is extracted incrementally into fleet, incident, security/exposure, baseline and alert controllers/engines. This avoids a high-risk rewrite and keeps each commit release-buildable.

The 2.0 domain is node-scoped: infrastructure nodes, services, endpoints, WireGuard metadata, monitoring, events, incidents, alerts, baselines, drift and backups carry a stable node UUID. Hosts are mutable connection attributes, not identity.

SQLite is the operational source of truth. Migrations use `PRAGMA user_version`, foreign keys, WAL and transactions. Secrets are excluded; SSH key paths and AdGuard credentials remain in Keychain/existing secure storage. Legacy Monitoring JSON is imported with UUID deduplication and retained during compatibility.

Remote discovery remains read-only. Existing writes still require explicit Write Mode and matching helper 1.2.1. Topology, exposure, drift, incidents and alerts never change VPS configuration.

## Swift application

TunnelDeck is a native SwiftUI macOS application. `AppViewModel` owns cached UI state and coordinates actor-based services. Views never construct shell commands. Parsers transform command output into typed models before presentation.

## SSH

`SSHService` invokes `/usr/bin/ssh` directly through `Process`, uses key-only batch authentication, a bounded timeout, cancellation, `IdentitiesOnly=yes`, and strict known-host checking. The default identity is `~/.ssh/id_ed25519` and can be changed during onboarding. The private key remains a filesystem reference and is never copied into the application or VPS.

## Security model

Read operations are fixed `ReadCommand` cases in `ReadOnlyCommandPolicy`. Write operations are fixed `WriteHelperCommand` cases validated by `WriteCommandPolicy`. There is no arbitrary command field, `eval`, `bash -c`, or raw remote editor.

Write Mode is separately gated in Settings and requires explicit confirmation. It does not disable Read Only Mode. UI controls additionally require an exact helper-version match.

## Server helper

`ServerHelper/tunneldeck-helper` is a versioned Python 3 program intended for `/usr/local/libexec/tunneldeck-helper`, owned by root with mode `0750`. It uses `argparse` fixed subcommands, validates every input, invokes programs with argument arrays, and never invokes a shell.

Restore accepts only a backup identifier and typed operation. It resolves paths inside `/root/tunneldeck-backups`, rejects symlinks and traversal, verifies SHA-256, maps entries to an explicit allowlist, creates a rollback backup and applies files atomically. Raw target paths are never accepted from the UI.

## Transaction model

`ServerTransaction` defines `prepare`, `backup`, `preview`, `apply`, `validate`, and `rollback`. The helper implements the critical WireGuard transaction directly: backup, candidate generation, `wg-quick strip` validation, atomic write, live `wg set`, health validation, and restoration plus `wg syncconf` on failure.

## Backup model

Server backups reside under `/root/tunneldeck-backups/YYYY-MM-DD_HH-MM-SS_microseconds_operation/`. Each includes only relevant configuration files, `wg show dump`, `iptables-save`, routes, and a `manifest.json` containing hashes and pre-health state.

## Secret handling

Normal SSH output is redacted before entering logs or UI. Client configurations use a dedicated sensitive-return method and are written directly to `~/Library/Application Support/TunnelDeck/Profiles/` with directory mode `0700` and file mode `0600`. QR codes are generated locally. PrivateKey, PresharedKey, passwords, Authorization/Bearer headers, cookies and UUID-style secrets are removed from safe logs.
