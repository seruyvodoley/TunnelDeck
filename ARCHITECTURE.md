# TunnelDeck Architecture

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
