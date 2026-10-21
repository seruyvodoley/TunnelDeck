# Home VPN Transport: audit and safe rollout plan

**Audit date:** 2026-10-21  
**Result:** router and VPS inspected read-only. No router, VPS, firewall, DNS, DHCP, WireGuard, or AmneziaWG configuration was changed. No additional hardware was purchased.

## Findings from the live system

### Xiaomi Router 4C

| Item | Observed |
| --- | --- |
| Board | Xiaomi Mi Router 4C; the installed firmware does not report a separate hardware-revision number |
| SoC / CPU | MediaTek MT7628AN, MIPS 24KEc V5.5 |
| Firmware | OpenWrt 25.12.5, revision `r33051-f5dae5ece4`, kernel 6.12.94 |
| RAM | 58,004 KiB total; about 14,980 KiB available in the sampled idle state |
| Flash | OpenWrt device data lists 16 MB raw flash. The live `/overlay` filesystem is 8.9 MiB total with about 7.0 MiB free |
| Swap | None |
| CPU sample | 90% idle, 9% system in one `top` sample; this is not a load benchmark |
| Foreign policy | Rule priority 1168, mark `0x68`, table alias `td_foreign`, default route through `awgtd0` |
| Existing traffic | `awgtd0` counters were approximately 143 GB received and 86 GB sent at observation time; counters are cumulative, not throughput |
| REALITY client | Neither `xray` nor `sing-box` binary/process was found |
| IPv6 | Only link-local addresses/routes were present; the local ULA prefix is explicitly unreachable. No global IPv6 route was observed |

These limits rule out installing a second proxy core on this router: only about 15 MiB RAM and 7 MiB overlay space are free, while the current policy gateway, DNS, Wi-Fi, and AmneziaWG already run there. Do not try to compensate with swap on flash.

### VPS

- Ubuntu Server 24.04.5, one vCPU, about 1.4 GiB available RAM at the sample, and about 7 MiB used by the Xray service.
- Xray 26.3.27 is active and enabled. `xray run -test` returned `Configuration OK`; TCP 8443 is listening.
- Caddy owns the TCP 443 listener. The `caddy.service` unit reported inactive while a `caddy` process owned the listener, so service-manager state alone is not used as a Caddy health check.
- `wg-quick@wg0`, `tunneldeck-awgtd0.service`, and `tunneldeck-firewall.service` reported active. The existing VPS policy table 167 still has its `homeexit` default route.
- The existing REALITY profile previously passed an end-to-end IPv4 transfer from the Mac through a local Xray SOCKS client. That verifies the VPS endpoint/client profile, not transparent home-network routing.
- The existing server profile is VLESS + REALITY + `xtls-rprx-vision` over TCP. The official Xray documentation limits Vision to TCP+TLS/REALITY combinations; the present server does not expose a native UDP listener.
- Read-only inspection of the live Xray JSON found two VLESS client entries, both with `flow: xtls-rprx-vision`, on a `raw` TCP / REALITY inbound at 8443. Xray's Vision inbound handler rejects VLESS UDP commands. Therefore the existing Vision identities can serve the TCP path, but UDP through XUDP is **not confirmed and should be treated as unsupported for those identities**. Full UDP coverage needs an additive VLESS identity with empty flow (and an XUDP sing-box outbound), then a config validation and controlled Xray reload; keep the existing Vision identities intact. XUDP remains UDP carried inside TCP and will have different loss/latency behavior from native UDP.
- Xiaomi has `nft` and OpenWrt `fw4`. Its existing `/usr/local/sbin/tunneldeck-home-split` owns table `inet tunneldeck`, the `ru4` set, and a `br-lan` prerouting mangle chain; the chain exempts local ranges, two reserved clients, and VPS `91.196.32.58`, then marks the remaining home IPv4 traffic `0x68`. `ip rule` priority 1168 sends that mark to table 168 (alias `td_foreign`), whose default is `awgtd0`. The router's main default is via `192.168.0.1` on `br-lan`. The script deletes/recreates only `inet tunneldeck` when it refreshes. This makes a separate nft table and separately owned policy rule feasible without rebuilding AWG, subject to a collision/order/forward-chain check at deployment time.

No Xray reinstall, Caddy edit, or VPS route change was needed for this audit.

## Recommended target architecture

Keep Xiaomi as the household AP, DHCP/DNS service, and existing policy router. Keep the current AmneziaWG route available as the immediate rollback. Add a separate always-on wired gateway for the REALITY client; the MacBook must not be part of the forwarding path.

The new gateway should be a small Linux x86-64 appliance with at least two Ethernet ports, 4 GB RAM, and 16–32 GB SSD/eMMC. A dual-port appliance keeps the transit path easy to inspect and avoids putting the router's core services on the constrained Xiaomi. No model or purchase is selected in this change; price, noise, and placement were not specified.

For the client core, sing-box is the leading candidate for the separate Linux gateway: its documented VLESS outbound supports `xtls-rprx-vision`, TLS REALITY settings, and XUDP packet encoding; its Linux TUN inbound supports `auto_redirect`/nftables transparent routing, including OpenWrt `fw4` compatibility. This is a compatibility-based recommendation, not a deployment or performance result. The exact client profile must first be generated from the protected server credentials and validated against the live Xray server.

TCP is carried by VLESS over the current REALITY/TCP connection with the current Vision identities. The present server identities have Vision flow, which the Xray inbound handler rejects for UDP commands. If UDP is required, add a separate VLESS client identity with no Vision flow and use sing-box's XUDP packet encoding over the same REALITY/TCP inbound; the existing listener need not expose native UDP. This change is additive but requires validating the Xray config and planning a brief service reload. It is still UDP inside TCP and may have higher latency under loss. Do not label UDP as verified until DNS, QUIC, and representative UDP applications pass the isolated-gateway tests.

### Staged route design

1. Preserve the current Xiaomi `ru4`, DIRECT path through AX18, exception list, AWG interface, DNS, and existing `0x68` policy while a test gateway is brought online.
2. Give the gateway a reserved LAN address and a route back through Xiaomi. Exclude its own Xray/sing-box process and the VPS endpoint from interception to prevent loops.
3. Add a separately named policy table/mark for a single test device or selected source. Do not flush or overwrite `td_foreign`, `0x68`, or the AWG table. A missing gateway route must fail closed for the selected VPN-only traffic; it must not fall through to Xiaomi's DIRECT default.
4. Keep RFC1918, router management, and local DNS destinations outside the tunnel. Apply the foreign mark to the same traffic classes as the existing policy, then verify both DNS and external exits before expanding device coverage.
5. Only after successful tests expose a manual AWG/REALITY selector in TunnelDeck. The selected mode must be applied as one bounded route/rule transaction with a timed rollback to the prior AWG route. Automatic failover remains off until both paths have repeated real connectivity checks.

The exact mark, table ID, firewall chain, and rollback commands must be chosen from a fresh collision/configuration audit immediately before deployment; this report intentionally does not reserve numbers or install a speculative ruleset.

## Router choices and hardware sizing

### TP-Link Archer AX18 on stock firmware

The Archer AX18 remains useful as the existing upstream Wi-Fi router, but its stock VPN Client is not a VLESS client. TP-Link's official AX18 V1 release notes add a generic VPN Client feature; TP-Link's VPN Client guidance describes named formats such as OpenVPN, WireGuard, and L2TP/IPSec. The AX18 release notes do not list VLESS/REALITY, and the installed router's authenticated hardware/region/firmware screen was not available in this read-only audit. The conclusion is therefore about documented stock support: no documented way exists to import this VLESS + REALITY + Vision profile or run an arbitrary Xray/sing-box core, and no firmware change is recommended. The official AX18 datasheet confirms a Gigabit WAN port and three Gigabit LAN ports, so it can remain the wireless/uplink device for a service up to 1 Gb/s.

**Conclusion:** no purchase or firmware change is needed for AX18; retain it as the Wi-Fi/uplink router. It can continue serving Wi-Fi while Xiaomi or a new OpenWrt device handles policy routing. If AX18 is the only wireless AP, keep it in place during a router replacement and change roles only after a separate Wi-Fi coverage test.

### Option comparison

| Option | Added cost | REALITY capability | Performance headroom | Complexity / impact | Failure behavior |
| --- | --- | --- | --- | --- | --- |
| Keep AX18 stock as client | None | VLESS/REALITY support is not documented; current profile cannot be used | Not applicable | Lowest change, but does not meet the requirement | Existing network unchanged; no REALITY path |
| Add a separate Linux gateway behind Xiaomi | Medium: gateway, power supply, storage, possibly cabling | Full sing-box VLESS+REALITY client; keeps the existing VPS endpoint | High with x86; easy to benchmark and replace independently | Medium; one new next hop and one test device first. Xiaomi, AX18, DHCP/DNS, and AWG remain in place | Timed policy rollback restores the present AWG route; gateway can be bypassed for management |
| Replace Xiaomi with a current OpenWrt router | Medium to high: new router plus possible AP/switch changes | Full client support on OpenWrt, with routing and client on one supported device | Medium to high depending on SoC; less x86 headroom per dollar | Highest impact: migrate DHCP, DNS, firewall, RU prefixes, marks, AWG, and management paths; revalidate every existing role | Single device failure can affect Wi-Fi/router services and both VPN paths unless a spare rollback router is kept |

**Preferred path:** separate gateway first. It provides the smallest change to the working network and gives a real test of the current VLESS endpoint with home traffic. Consider replacing Xiaomi only if keeping two boxes is undesirable or the gateway test proves that the current OpenWrt/PBR layout cannot safely select traffic. AX18 cannot substitute for either option as a REALITY client.

For a concrete supported OpenWrt replacement candidate, the GL.iNet GL-MT6000 (Flint 2) is listed by OpenWrt with a four-core MT7986AV at 2 GHz, 1 GiB RAM, 8 GiB eMMC, two 2.5 GbE ports and four 1 GbE ports. This is a good integrated-router candidate on paper, but it still requires a full config migration and a real Xray/sing-box throughput test. A FriendlyElec NanoPi R4S (4 GB) is a lower-radio-impact alternative only if used as a wired router behind/alongside AX18: official OpenWrt data lists 4 GB RAM and two 1 GbE ports; it has no Wi-Fi. Hardware availability and local prices fluctuate, so the comparison is intentionally relative: using AX18 costs nothing; the separate gateway is a one-device addition; replacing Xiaomi is the largest one-time hardware and migration cost. Do not buy until the measured WAN tier and whether Wi-Fi will stay on AX18 are confirmed.

### Minimum and recommended gateway specification

The WAN subscription and a measured baseline speed were not present in router discovery, so a precise speed target cannot honestly be claimed. The AX18 class is Gigabit Ethernet; if the ISP service is at or below 1 Gb/s, the following is the practical sizing:

| Use | Minimum to pilot | Recommended for whole-home use |
| --- | --- | --- |
| CPU | Supported 64-bit ARMv8, 4 cores, roughly 1.5 GHz or better | Intel N100/N150 class x86-64, 4 cores, AES acceleration, or newer |
| RAM | 2 GB | 4–8 GB |
| Storage | 8 GB reliable eMMC/SSD | 32 GB or larger SSD/eMMC with spare capacity for logs and rollback image |
| Networking | Two stable 1 GbE interfaces or one routed 1 GbE interface for the behind-Xiaomi design | Two Intel-based 2.5 GbE ports for a standalone gateway, or two 1 GbE ports when the measured service is ≤1 Gb/s |
| Expected line rate | Benchmark required; no published hardware number is assumed | Aim to sustain at least 1.25× the subscribed downlink/uplink in both directions in a lab test before migration |

For service above 1 Gb/s, use 2.5 GbE end-to-end and an x86-64 CPU with enough single-core and cryptographic headroom; the current AX18/Xiaomi path itself may then be the bottleneck. The REALITY encryption and TCP encapsulation cost varies with profile, packet size, and loss. Choose by a sustained bidirectional benchmark using the actual sing-box build and the actual VPS, not by a VPN vendor's headline speed. Leave CPU headroom for nftables, DNS, routing and concurrent clients.

## Detailed separate-gateway traffic design

### Placement and traffic path

For the first pilot, connect a wired Linux gateway to the same home LAN behind Xiaomi and assign it a DHCP reservation. Give one test device a fixed DHCP lease. Xiaomi remains the home policy router and keeps the current `0x68`/table 168 (`td_foreign`) → `awgtd0` route intact. A clean pilot can use a separately owned nftables table (for example `inet tunneldeck_reality`) with its own prerouting chain and a separately audited fwmark/rule/table. The chain can run after the existing `mangle` classifier and change only packets from the pilot source that the current chain already marked `0x68`; that reuses the known foreign-vs-RU/DIRECT classification and avoids copying or replacing its RU prefix set. The pilot policy rule must match only the new mark and have priority before 1168. The new table routes to the gateway LAN address and uses an explicit unreachable fallback if that next hop disappears. This can use one NIC in routed mode; a second NIC is useful for a physically isolated test segment or inline deployment, but it is not a prerequisite for a next-hop pilot. Verify chain priorities, fw4 forward acceptance and mark allocation from the live snapshot before choosing exact values.

Traffic flow:

```text
Test device → Xiaomi (classify foreign destination) → Linux gateway TUN → VLESS/REALITY TCP → VPS Xray :8443 → foreign egress
                                            ↘ gateway's own VPS connection → Xiaomi/AX18 → Internet
```

The gateway runs sing-box with a TUN inbound and a VLESS outbound matching the existing Vision/REALITY server profile. Its Linux forwarding firewall admits only the selected client subnet/source and local management. For home-client responses, the TUN reinjects the return packet toward the connected home LAN so the gateway ARPs for and delivers it to the original client. Keep the original source address visible on the LAN side unless testing shows the current Xiaomi firewall/conntrack or gateway behavior requires SNAT; if SNAT is required, use a narrowly scoped mapping and verify per-client DNS and logs still identify the test device. Do not apply broad masquerading speculatively.

The gateway's own REALITY connection must leave toward the VPS through Xiaomi/AX18 directly. Exclude the VPS endpoint IP and port from Xiaomi's foreign selection and from the gateway TUN interception. The existing Xiaomi classifier already exempts `91.196.32.58` for all home LAN sources; preserve that rule and confirm it still matches the live server endpoint. Also bypass the gateway's own process/mark, local LAN and management prefixes, Xiaomi/AX18 addresses, and DNS upstream traffic as designed. This avoids sending the encrypted transport back into itself or into the existing AWG tunnel. Confirm the actual public endpoint and route before writing any new exception; do not hard-code a guessed VPS IP in the app.

### TCP, UDP, DNS, IPv6, and routing loops

- **TCP:** TUN captures selected client flows. sing-box opens the VLESS+REALITY Vision TCP session to the current Xray listener. VPS Xray exits to the Internet using its existing policy. No Caddy port or listener change is needed for the current 8443 endpoint.
- **UDP:** the existing VLESS identities are configured for Vision, and Xray rejects UDP commands under that flow. First add one separate no-flow VLESS identity on the current REALITY/TCP listener, then route selected UDP via sing-box's XUDP packet encoding. The existing listener does not need a native UDP socket. This is still carried over TCP and can suffer head-of-line delay. Validate DNS UDP/TCP, QUIC, video calls, and a sustained UDP test separately; do not promise native UDP performance. If server-side additive user provisioning is out of scope, keep home UDP on the current AWG path and report the REALITY pilot as TCP-only.
- **DNS:** Xiaomi's current custom chain marks its own UDP/TCP DNS queries to `1.1.1.1` and `1.0.0.1` with `0x68`, so those currently use AWG even if one client's other foreign traffic is selected for REALITY. For the pilot, set only the test device to use a resolver on the new gateway (static DNS on that test device, or a per-client DHCP option); have that resolver send upstream through the VLESS path. For full rollout, either direct the LAN's per-client DNS to the gateway or add a separately audited router-output policy. Explicitly handle TCP/UDP port 53 and decide how encrypted DNS (DoT/DoH) follows the foreign policy. Test for DNS leaks by observing the resolver from the test device and at the VPS; a green Xray service alone is not DNS evidence.
- **IPv6:** the Xiaomi audit observed no global IPv6 route. Keep the pilot IPv4-only until IPv6 is separately discovered and tested; if IPv6 is enabled upstream, either tunnel selected IPv6 too or block it for the pilot device to prevent bypass.
- **Loop prevention:** exclude the Xray server endpoint and gateway-originated transport packets from the TUN route; bind the VLESS outbound to the actual Xiaomi-facing interface or use a dedicated routing mark/table. Test the gateway's own DNS and NTP without the tunnel. Put local subnets and the management route ahead of the TUN route. A monitor must alert if the VPS endpoint route ever resolves back through the TUN.
- **Marks and existing AWG:** use a newly audited mark/table and a rule with priority ahead of the existing foreign rule only for the single test source. Do not reuse or flush `0x68`, `td_foreign`, `awgtd0`, the current nftables sets/chains, or the AmneziaWG configuration. Mark/route ownership must be explicit; preserve the current AWG path as the rollback target. Existing policy can be tested with read-only `ip rule`, `ip route`, and `nft list ruleset` snapshots before and after each staged transaction.

Xiaomi's existing nftables and policy routing prove that it already classifies home traffic by RU/DIRECT vs foreign and sends foreign packets through a dedicated table. A later chain can override only the pilot packet mark after this classifier; a separately owned table can hand those packets to a new next hop. The fw4 forward chain currently permits routed LAN traffic toward `br-lan`, but the full gateway return behavior still needs a packet-level test. The existing `td_foreign`/168 table is currently the AmneziaWG route and stays intact throughout the pilot. The Xiaomi refresh script also recreates `inet tunneldeck`, so the REALITY pilot must live in a separate table and a separately managed init/watchdog script; never append disposable rules to the table that refresh deletes.

## Safe migration and acceptance plan

No live routes or services were changed during this audit. The following is a deployment plan, not a record that REALITY home routing has already been completed.

1. **Capture a baseline.** Export Xiaomi UCI, firewall/nftables rules, `ip rule`, all route tables, DHCP leases, DNS settings, AWG config metadata, and AX18 WAN/LAN/Wi-Fi settings. Store protected copies locally. Record a working test device's direct/AWG behavior, DNS resolver, RU IP check, foreign IP check, speed, latency and packet loss.
2. **Prepare and bench the candidate offline.** Validate the TCP Vision profile on a separate gateway. For UDP, first prepare an additive no-flow VLESS identity on VPS, run Xray's config test, record a protected backup and schedule a brief reload; do not modify the two existing Vision identities. Then validate sing-box XUDP, DNS, QUIC, load, memory, reboot behavior and fail-closed operation without connecting it as a home next hop. Verify the VLESS endpoint bypass and direct path with route tracing.
3. **Pilot one wired device.** Reserve one source address and select only foreign destinations for that source with a temporary, separately named rule/table. Keep the existing `0x68` AWG rule available unchanged for all other devices and as the return route after rollback.
4. **Arm automatic rollback before applying.** Snapshot the exact active rules, install an independent watchdog on Xiaomi with a short expiry (initially 5 minutes), then apply only the temporary test policy. If the management session drops, test health checks fail, or confirmation is not received, the watchdog deletes the pilot rule/table and restores the exact prior temporary state. Reboot before making the pilot policy persistent to confirm the router returns to its original AWG configuration. Do not rely on an app-side timer for rollback.
5. **Acceptance checks.** Confirm real TCP data transfer through the VLESS gateway, expected foreign VPS egress, expected RU/direct egress, DNS resolver/egress, UDP DNS and QUIC behavior, no IPv6 bypass, no VPS-endpoint loop, and no change to AWG counters/routes for non-test clients. Test gateway process stop, gateway power loss, DNS failure, VPS failure and Xiaomi reboot; verify the test source fails closed until watchdog restores AWG, while every non-test device remains usable.
6. **Soak and expand.** Keep one device on the path for at least 24 hours including video/voice and sleep/reconnect cycles. Then opt in devices in small groups, retaining the timer for each change and checking route, DNS and throughput evidence. Change policy from one test source to the home subnet only after acceptance and retain a one-command rollback to the existing AWG selector.
7. **Only then automate in TunnelDeck.** Show REALITY as `Configured` only when client configuration, endpoint bypass, active tunnel/session counters and a successful external probe are observed. Show `Degraded` or `Unknown` on stale/missing evidence. Any selector must show the current AWG/REALITY path and arm its rollback before applying policy. Keep the router's raw evidence and freshness visible.

## Home VPN Transport monitoring scope

TunnelDeck now reports the discovered home foreign route and its AmneziaWG interface, Xiaomi's available CPU/RAM/overlay and whether Xray/sing-box binaries exist there, the VPS Xray listener state, and the observed RU prefix count. This accurately exposes why Xiaomi is not a viable client host. It does **not** report a home REALITY gateway, session success, UDP health, or all-device reachability until a separate client exists and those signals are implemented and observed. VPS Xray active is server status only; it is never treated as proof that home devices traverse REALITY.

## Tests and remaining work

### Completed in this audit

- Read-only SSH audit of Xiaomi and VPS.
- Verified the active Xiaomi policy rule and AWG default route.
- Verified that no `xray` or `sing-box` client is installed/running on Xiaomi.
- Verified current router RAM, overlay space, firmware, CPU, and IPv6 route state.
- Verified Xray service state, config validation, listener, memory use, and the current 443 listener owner.
- Ran the TunnelDeck test suite after adding parser coverage for resource headroom and REALITY-client detection: 80 tests passed.

### Not performed

- No package installation or router/VPS/network configuration change.
- No transparent TCP/UDP/DNS test through a home REALITY gateway, because no compatible home-side client exists.
- No AWG-versus-REALITY throughput, latency, multi-device, failover, reboot, or leak test. The old Mac SOCKS transfer is not a comparable AWG baseline.
- No global IPv6 test; none was advertised on Xiaomi in the current sample.

The central acceptance criteria—multiple home devices using REALITY, safe transport switching, fail-closed behavior, and comparative speed—cannot be declared complete without the always-on gateway. No benchmark result is inferred from interface counters or server status.

## Files changed in this audit

- `Sources/TunnelDeck/Models/HomeInfrastructureModels.swift` — gateway CPU/RAM/overlay and client-presence fields.
- `Sources/TunnelDeck/Security/CommandPolicy.swift` — read-only discovery of resource headroom and Xray/sing-box presence.
- `Sources/TunnelDeck/Services/HomeInfrastructureDiscoveryService.swift` — parsing for the added discovery sections.
- `Sources/TunnelDeck/Views/InfrastructureViews.swift` — truthful Home VPN Transport status card; no nonfunctional switch controls.
- `Tests/TunnelDeckTests/HomeInfrastructureTests.swift` — parser coverage.
- `HOME_VPN_TRANSPORT_AUDIT.md` — this audit and rollout plan.

## Rollback

This audit made no changes to live network configuration, so router/VPS network rollback is not needed. To remove only the application change, revert the commit containing these files. Once a separate gateway exists, its deployment must create a fresh backup and a timed rollback before changing even one test device's policy route.

## Primary references

- [OpenWrt Xiaomi Mi Router 4C device data](https://openwrt.org/toh/xiaomi/xiaomi_mi_router_4c)
- [TP-Link Archer AX18 V1 official firmware notes](https://www.tp-link.com/uk/support/download/archer-ax18/?app=t)
- [TP-Link VPN Client protocol guidance](https://www.tp-link.com/uk/support/faq/4654/)
- [TP-Link Archer AX18 official datasheet](https://www.tp-link.com/uk/document/43443/)
- [OpenWrt GL.iNet GL-MT6000 hardware data](https://openwrt.org/toh/hwdata/gl.inet/gl.inet%20gl-mt6000)
- [OpenWrt NanoPi R4S hardware data](https://openwrt.org/toh/friendlyarm/nanopi_r4s_v1)
- [sing-box VLESS outbound](https://sing-box.sagernet.org/configuration/outbound/vless/)
- [sing-box Linux TUN and auto-redirect](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [Xray VLESS and Vision flow](https://xtls.github.io/en/config/inbounds/vless.html)
- [Xray VLESS inbound UDP handling](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/inbound/inbound.go)
- [Xray transport and Vision combinations](https://xtls.github.io/en/config/transport.html)
