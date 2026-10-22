# VLESS + REALITY deployment and test report

Status: **deployed on the VPS and end-to-end IPv4 tested from the Mac**  
Date: 2026-10-21 (Asia/Krasnoyarsk)  
Branch: `feature/homeexit-resilience-20261022`

## Audit findings

- The active repository is `/Users/serg/TunnelDeck`, branched from `06f86aa`. The separate `TunnelDeck-2.2.2` checkout was left untouched.
- TunnelDeck is a native macOS 14+ infrastructure dashboard. It has no Network Extension target, Xray client, or Android app. The app can report Xray service telemetry, but it cannot itself activate a full-device VLESS tunnel.
- Before deployment, the VPS had Ubuntu Server 24.04.5, 1 vCPU, about 1.9 GiB RAM, 512 MiB swap, and 25 GiB disk. Xray, NGINX, and 3X-UI were absent.
- Caddy ran in the `ma-alice-https` Docker container and owned TCP/UDP 443. That listener/container was not changed. The new listener uses TCP 8443 only.
- Before deployment, `wg0`, `homeexit`, `awgtd0`, the custom firewall, and the existing `fwmark 0x67` / table `167` rule were active. `tdhome` is the OpenWrt peer, not a separate VPS interface. No home-router configuration was changed.
- The RU route service had `RemainAfterExit=yes` despite being a timer-triggered oneshot. Its 12-hour timer had no next trigger. A narrow systemd drop-in now lets each refresh exit so the timer runs again.
- SSH to `root@10.68.0.1` worked throughout over the overlay. No SSH repair was required.

## Deployment choices and changes

- Installed official Xray-core `26.3.27` for Linux amd64, after SHA-256 verification (`23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae`). The same official release was used for the Mac arm64 test client.
- Configured VLESS + REALITY + `xtls-rprx-vision` with Xray `raw` TCP transport on TCP 8443. Xray warns that using a non-443 port can be more detectable; 8443 was selected as the separate test port while Caddy keeps 443.
- Selected `www.wikipedia.org:443` as REALITY target/SNI after repeated direct TLS 1.3 handshakes from the VPS, verified certificate chain, ALPN `h2`, and a successful Xray TLS probe. `www.microsoft.com` also passed the checks but was not configured. A target change requires re-testing from the VPS.
- Installed `xray.service` as an unprivileged `xray` user with systemd hardening, warning-only journal logs, no access log, and no extra capability. Server config is `root:xray` mode `0640`.
- Added one inbound firewall allow for TCP 8443 to the existing `TUNNELDECK_INPUT` chain. Added a dedicated Xray policy service which marks only new Xray connections to destinations in `td_ru4`, saves/restores mark `0x67` on that connection, and SNATs Xray flows leaving `homeexit` to its expected address `10.67.0.1`. This uses existing table 167 and existing route/interface; it does not flush or replace the firewall.
- Refreshed `td_ru4` from RIPE using the existing script after fixing the timer drop-in; it contained 11,482 prefixes at the final check. The existing mark rule and table remained in place.
- Added TunnelDeck read-only telemetry for the Xray unit and TCP listener, separate from exit-routing state. No private key, UUID, or profile content is read by the app.
- Root-only before-state and rollback snapshot: `/root/tunneldeck-backups/reality-20261021-1520`.

Repository files added or changed:

- `REALITY_SETUP.md`
- `REALITY_ROLLBACK.md`
- `REALITY_TEST_REPORT.md`
- `ops/reality/` contains the redacted Xray config template, systemd units, firewall snippet, route-policy script, and RU timer override template.
- App telemetry/parser/UI changes are in the infrastructure model, discovery command/service, view, reset path, and one parser test.

Generated device profiles and key metadata are kept outside Git in `~/.config/tunneldeck/reality/` with mode `0600`. They are not included in this report or repository.

## Verification results

| Component | Before | After | Verified after deployment |
|---|---|---|---|
| WireGuard `wg0` | Active, recent peer handshakes | Active | Yes; service and interface remained up |
| AmneziaWG `awgtd0` | Active under custom TunnelDeck unit | Active | Yes; service and interface remained up |
| `homeexit` | Active, recent peer handshake | Active | Yes; service and table 167 route remained up |
| `tdhome` | Active on OpenWrt (`10.66.66.6/32`) | Unchanged | Router was read-only checked; no changes made |
| Caddy | Docker container owned 443 | Same container owns TCP/UDP 443 | Yes; container running and listener present |
| VLESS + REALITY | Not installed | Xray 26.3.27, enabled, TCP 8443 | Config test, service restart, public TCP connect, and real transfers passed |
| RU split | `td_ru4`, mark `0x67`, table 167, `homeexit` | Same path plus Xray-scoped conntrack mark/SNAT | RU IP echo returned the home public IP; HTTPS to Yandex completed |
| Foreign split | VPS default route on `ens3` | Unchanged for unmarked Xray destinations | Three IP-echo checks returned the VPS public IP; Wikipedia HTTPS returned 200 |
| SSH | Available over the `10.68.0.1` overlay | Still available | Repeated SSH commands succeeded |

End-to-end Mac test used the official Xray client locally with SOCKS5 at `127.0.0.1:10808`; the client did not change system-wide routes. The foreign IP echo returned the VPS address three times. A RU-classified IP echo endpoint (`whatismyip.ru`, address confirmed in `td_ru4`) returned the observed home-exit address. `www.wikipedia.org` returned HTTP 200; `yandex.ru` returned its expected HTTP 302 redirect. The Xray server was restarted with the validated production config before these final checks. Stopping the local client ended only that client session.

The Mac and server Xray configs both passed `xray run -test`. The Mac client connected to the public TCP/8443 listener. Route lookups showed a marked RU destination using `homeexit` / table 167 / source `10.67.0.1`, while an unmarked foreign destination used `ens3`. Xray was enabled and active after the service restart; the observed service memory was about 9 MiB. The TCP/443 listener and Caddy container remained present.

## Not measured or not tested

- No comparable WireGuard RTT or throughput baseline was collected: the Mac test used a local SOCKS client, not an active Mac WireGuard client profile. The single HTTPS request timings are not a throughput benchmark.
- Android/Samsung import, mobile-operator behavior, full-device routing, and Android disconnect/reconnect were not tested. Import the private `android.vless.txt` URI into an official Android client supporting VLESS + REALITY + Vision.
- No VPS reboot, forced DNS failure, homeexit outage, or deliberate production server outage test was performed. The service’s `ExecStartPre` config validation, controlled Xray restart, unit enablement, firewall persistence script, and route timer schedule were checked instead.
- There is no automatic transport failover or macOS system VPN integration. The TunnelDeck UI reports server-side Xray state only; the actual tunnel profile is still used by a compatible client.
- Xray logs a warning that TCP/8443 is less conventional than 443. Caddy occupies 443, so it was not displaced or reconfigured.

Rollback steps are in `REALITY_ROLLBACK.md`. They remove only the Xray additions and explicitly avoid applying a stale whole-firewall snapshot.

## Independent XHTTP fallback deployment (2026-10-23)

- Added `tunneldeck-xray-xhttp.service` with a separate Xray-core `26.10.21` binary and a dedicated XHTTP-only config. The existing Xray `26.3.27` service, VLESS + REALITY Vision listener on TCP/8443, and its client profiles were not replaced or restarted during the fallback setup.
- Added one TCP/2053 accept in the existing firewall chain and the persistent TunnelDeck firewall script. TCP/443 remains owned by the original Caddy container. No WireGuard, AmneziaWG, homeexit, policy rule, table, or home-router configuration was modified.
- The first candidate target, `www.microsoft.com`, triggered Xray's own warning that it increases the likelihood of blocking. It was not used by any client; the service and private profiles were switched to the already-tested `www.wikipedia.org` target before client validation. The probe confirmed TLS 1.3; the endpoint did not negotiate X25519MLKEM768, so the profile uses conventional X25519. Xray still warns that a non-443 REALITY listener is more blockable; Caddy prevented a safe same-port test.
- Config validation passed as the unprivileged `xray` account. TCP/2053 became publicly reachable. The Mac client config passed validation and used a local SOCKS5 listener on `127.0.0.1:10888`; macOS system proxies and default routes remained unchanged.
- Real transfers through XHTTP + REALITY passed: the foreign IP-echo matched the VPS public egress, the Russian `/api/ip` endpoint matched the direct home egress, and the observed HTTP responses were Wikipedia `200`, Google generate_204 `204`, and Yandex `302`. The endpoint resolved into `td_ru4`, so this also exercised the existing `0x67`/table-167/homeexit routing.
- After successful transfer checks, the temporary 20-minute rollback timer was cancelled. A root-only backup and a narrow rollback script remain on the VPS at `/root/tunneldeck-backups/reality-20261023-xhttp`.
- TunnelDeck's topology and Network Health discovery now report TCP/8443 and TCP/2053 as separate server transports. They still do not claim that a phone or home router is connected merely because a listener is green.

## Caddy TLS XHTTP fallback (2026-10-23)

- Added `tunneldeck-xray-xhttp-tls.service` bound only to `127.0.0.1:2054`; it uses the same per-device VLESS identities as the XHTTP REALITY fallback and the existing Xray policy UID. The service has its own minimal XHTTP `security=none` inbound; Caddy terminates ordinary TLS on its existing TCP/443 certificate and reverse-proxies only the XHTTP path over h2c.
- Added one Caddy path handler. The public firewall and port mappings did not change. TCP/443 stayed owned by `ma-alice-https`; the existing Caddy webhook route, 8443 Xray service, 2053 REALITY fallback, WireGuard/AmneziaWG, `homeexit`, and all routing rules remained active.
- Caddy configuration and Xray config both validated before activation. The new service passed its systemd Xray preflight and bound only `127.0.0.1:2054`. A temporary 15-minute rollback was armed before Caddy reload and cancelled after data-plane verification.
- Used the protected Mac profile with the bundled Xray core 26.3.27, through a local SOCKS port only; no macOS system proxy, TUN, or default route was changed. Happ Plus imported the new profile and returned a 617 ms ping result; the previous selected profile remained selected.
- Real HTTPS transfers through the Caddy/TLS/XHTTP path succeeded for both foreign and Russian checks. Foreign egress matched the VPS default egress. Russian egress matched the Mac's direct home split-routing result, confirming the existing RU policy still sends those requests through `homeexit`.
- The new TLS profile and Samsung QR are local files with mode `0600` under `~/.config/tunneldeck/reality/`; no credentials are in this repository. The Mac GUI profile is imported but not activated as a system-wide tunnel.

This is a standard TLS fallback behind Caddy, not REALITY on port 443. It improves reachability when nonstandard listener ports are filtered, but it does not make the endpoint indistinguishable from a website and cannot prevent IP or domain blocking. The 2053 REALITY and 8443 Vision/REALITY entries remain available independently.

### Client integration status

The same XHTTP profile passed a real transfer using the Xray `26.10.21` command-line core. The v2rayN UI has the old 8443 profile selected and reports its probe delay, but its local listener at `127.0.0.1:10808` is not running; a local SOCKS request therefore fails until its core is started. This is client activation/UI integration, not evidence of a broken VPS transport. Happ's earlier TUN DNS failure remains a separate client-side issue; TUN mode was not enabled during the successful test.
