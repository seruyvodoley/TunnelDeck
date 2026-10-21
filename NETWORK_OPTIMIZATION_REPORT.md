# TunnelDeck network optimization and health audit

**Audit date:** 2026-10-22 (local); VPS observations were made over the existing private SSH path `10.68.0.1`.

**Change safety:** read-only infrastructure audit. No VPS, Xiaomi, AX18, tunnel, firewall, DNS, or route configuration was changed.

## Scope and starting state

The repository already contains topology discovery, WireGuard/AmneziaWG handshake and counter parsing, DNS path testing, health checks, backups, incident history, and recovery guidance. This pass added a bounded, manual VPS Network Health probe and made it visible in Diagnostics. It uses the application's whitelisted read-only SSH command path and records each run in the existing local diagnostic history.

The checkout is `/Users/serg/TunnelDeck`. Work is on `feature/network-health-recovery`, created from the existing `feature/tunneldeck-xray-reality-transport` branch so the already-dirty DNS-filtering work remained present. No user changes were reset.

## Observed VPS state

- Ubuntu host `a0392936711.serv.host`, uptime about 14 days 23 hours, load average below 0.3 during inspection.
- Available RAM about 1.37 GB; root disk 42% used with about 14.6 GB available; swap use about 79%. This is a point-in-time sample, not a load test.
- Main default route: `1.1.1.1 via 10.0.0.1 dev ens3`.
- Explicit RU-mark lookup: `77.88.8.8 mark 0x67` resolves to `dev homeexit table 167`. This confirms the kernel policy lookup, not that a packet followed it end to end.
- WireGuard/AmneziaWG interfaces observed: `wg0`, `homeexit`, `awgtd0`, and `awgfriend0`. Existing peer transfer counters were non-zero. No interface or peer was restarted.
- Xray's systemd unit is enabled/running and listens on TCP 8443. Its firewall accept rule and UID-based mark handling for RU destinations were present. Xray journal entries show successful accepted client sessions on 2026-10-21, but this pass did not initiate a fresh REALITY client session.
- AdGuard Home answered on `10.66.66.1:53`; the HTTP admin endpoint returned a redirect. `getent` resolved `example.com`; `resolvectl` reported about 15.8 ms in the sampled query.
- Caddy is in Docker container `ma-alice-https` (`running`, restart policy `unless-stopped`), not a host `caddy.service`. `systemctl` reporting that unit absent/inactive would be the wrong health signal. HTTPS to the configured `91-196-32-58.sslip.io` host completed TLS and returned HTTP 404, which is the configured catch-all behavior. A request by raw IP did not supply the right SNI and failed TLS; that is not evidence that the configured Caddy endpoint is down.
- The inspected firewall had established/forward rules and NAT paths for the existing VPN interfaces. The RU route mark and NAT counters were non-zero. No firewall rules were changed.

## Home gateway and home-network limits

The supplied VPS key reached `192.168.0.2` but was rejected by the router's SSH authentication. No key or router setting was changed. Therefore this pass could not independently collect the Xiaomi's current RAM/flash, complete nftables rules, DHCP leases, actual per-device exceptions, DNS forwarding path, IPv6 policy, or route counters. Values in the task description (OpenWrt 25.12.5, roughly 58 MB RAM, roughly 7 MB free overlay) remain user-provided orientation, not measurements repeated in this audit.

Because the router could not be authenticated, this audit does **not** confirm home-device Russian DIRECT, home-device foreign VPN, DNS fail-closed behavior, or the reachability of every existing device exception. The VPS route lookup is not a substitute for a home-origin packet test.

## Code changes

- Added a manual read-only VPS Network Health probe in **Diagnostics**. It checks main route lookup, RU-mark route lookup, DNS resolution, a bounded HTTPS/TLS request, Xray unit/listener, the Caddy container, and VPS resource headroom.
- The screen shows source and check time. It labels route lookup as simulated and explicitly says that server-side tests do not establish home-router forwarding or an active VLESS + REALITY client session.
- Probe runs are saved in the existing diagnostic history. The probe does not restart a service, add a route, or alter firewall state.
- Retained the pre-existing DNS filtering discovery/UI edits in the working tree.

## Changes on servers and routing

No changes were made on the VPS, Xiaomi, or AX18. Existing `wg0`, `awgtd0`, `homeexit`, `tdhome` and the newer `awgfriend0` setup were not restarted or edited. No routing, nftables, iptables, NAT, DNS, or IPv6 setting was changed. Existing backup/recovery mechanisms were not invoked because no remote configuration was changed.

## Tests and measurements

- Before edits: `swift test` passed all 80 existing tests.
- After edits: `swift test` passed all 83 tests. Three new parser tests cover a successful route/DNS/HTTPS/Xray/Caddy sample, failed probes, and SSH failure.
- A live, read-only execution of the same server probe returned: default route via `ens3`; mark `0x67` route via `homeexit`/table 167; DNS answer present; HTTPS 200 with TLS in about 37 ms and total about 52 ms; Xray active/listening on 8443; Caddy container running; resource state as above.
- A separate HTTPS request to Caddy's configured hostname returned 404 after a successful TLS handshake. It is a server-side configured-host check, not a REALITY test.
- No before/after speed benchmark was run. No throughput, jitter, packet-loss, or bandwidth claim is made. The checks are single bounded probes and do not load-test Xiaomi or the Internet link.
- No working tunnel was disabled to simulate a fault. Recovery behavior was not tested on live interfaces.

## Recovery, backups, and fail-closed behavior

The app already has scoped VPS backups before supported helper writes and verified restore previews. No helper backup was taken in this audit because it did not perform a write. A Mac-side protected backup catalog, router backup acquisition, and SSH-independent timed rollback for router route changes were not added here.

Automatic tunnel or route recovery remains disabled. The available evidence does not establish a safe, independent rollback path for changes to `awgtd0` or the Xiaomi's routing. DNS failures therefore must not trigger a VPN restart. Home-network fail-closed behavior for foreign destinations remains unverified; it was not changed because a guessed nftables guard could break Russian DIRECT or management access.

## Deliberately not changed

- No Xiaomi software install or firmware change, no new transport, and no equipment/service purchase.
- No mass tunnel, firewall, DNS, or router restart.
- No changes to device route policies or existing DIRECT exceptions.
- No automatic transport switching or speed ranking without route-confirmed measurements.

## Rollback and Git

The added app behavior can be reverted by reverting commit `97fb315`. No infrastructure rollback is needed because the infrastructure was read-only. The DNS filtering edits that were already in the checkout were retained and included with the related DNS discovery/UI work. Work is committed on `feature/network-health-recovery`; the branch is local and was not pushed.

## Recommended next steps

1. Restore or confirm a dedicated read-only SSH identity for Xiaomi `192.168.0.2`, then rerun a compact audit of resources, route rules, DNS, IPv6, `ru4`, and actual DIRECT exceptions.
2. Run a single-device end-to-end home test that records observed public egress on both DIRECT and VPN routes and confirms DNS behavior, without switching the whole LAN.
3. Only after those observations, design a timed, independently recoverable fail-closed rule and staged device rollout.
4. Add a real REALITY client probe only where a locally installed client profile can be used without exposing its secret; distinguish server listener health from client handshake and data-plane health.
5. Collect route-tagged measurements before changing Xiaomi policy, and compare like-for-like tests.
