# TunnelDeck VLESS + REALITY

## Current deployment

- Xray-core `26.3.27` runs as the `xray` system user under `xray.service`.
- Entry: TCP `8443` on the VPS. TCP/443 remains owned by Caddy; no Caddy listener or container was changed.
- Protocol: VLESS + REALITY + Vision (`xtls-rprx-vision`) over Xray `raw` TCP transport.
- REALITY target/SNI: `www.wikipedia.org:443`. It passed repeated TLS 1.3 handshakes, certificate verification, and ALPN `h2` checks from the VPS. `www.microsoft.com` was also checked as a possible replacement, but is not configured as an additional server name.
- Independent fallback entry: TCP `2053`, served by `tunneldeck-xray-xhttp.service` with its own Xray-core `26.10.21` binary and config. Protocol: VLESS + XHTTP + REALITY, `mode=auto`, path `/api/v3/updates`, with no Vision flow. It shares the existing Xray UID policy, so RU destinations still use mark `0x67` / table `167` / `homeexit` and foreign destinations use the VPS default route.
- HTTPS-fronted XHTTP entry: the existing Caddy listener and certificate on TCP `443` serve only the `/api/v3/updates*` route to a separate Xray service bound to `127.0.0.1:2054` using HTTP/2 cleartext on the private upstream. Client-to-Caddy uses normal certificate-validated TLS with XHTTP. This is a complementary TLS transport, not REALITY. It adds no public listener or firewall rule and leaves the existing Caddy webhook handler in place.
- The REALITY fallback uses `www.wikipedia.org:443` as its target/SNI. Xray's own config warning flags `www.microsoft.com` as a higher-risk target, so it was rejected. Wikipedia passed a TLS 1.3 probe but does not advertise X25519MLKEM768; this fallback therefore keeps the conventional X25519 handshake. Xray also warns that REALITY on TCP/2053 is more blockable than port 443. The TLS-fronted XHTTP route on Caddy :443 provides a standard HTTPS alternative; Caddy remains the owner of the public socket.
- The new inbound limits unauthenticated REALITY fallback transfer rates and rejects client/server clock skew beyond five minutes. It does not rate-limit authenticated VLESS sessions and does not change the existing 8443 inbound.
- Separate UUIDs were generated for the Mac and Android profiles. The server private key stays in `/usr/local/etc/xray/config.json`; client profiles and key metadata stay in `~/.config/tunneldeck/reality/` on the setup Mac, mode `0600`. Never copy them into this repository, support bundles, or issue reports.

The official Linux release archive was checked against SHA-256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` before installation. The Mac test client used the matching official arm64 archive and its published SHA-256.

## RU and foreign exits

Xray does not decide the exit country by transport. Its direct outbound sockets are marked only when a new destination address is in the existing `td_ru4` ipset. The VPS rule sends mark `0x67` through table `167` and `homeexit`; conntrack keeps that mark on later packets in the flow. A narrowly scoped SNAT rule gives those sockets source `10.67.0.1`, which is the address expected by the existing homeexit peer. Unmarked destinations leave through the VPS default route on `ens3`.

The public listeners have additive allow rules in the existing `TUNNELDECK_INPUT` chain for TCP/8443 and TCP/2053 on the VPS IPv4 address. No UDP port was opened. Xray also blocks private and link-local destination ranges. IPv6 has no public route on this VPS, so the services and their DNS strategy are IPv4-only.

`tunneldeck-xray-policy.service` restores the Xray routing/NAT rules after reboot. The supplied `tunneldeck-ru-route-override.conf` changes the existing oneshot service to exit after each run so its 12-hour timer can refresh `td_ru4` again. This corrects the pre-existing `RemainAfterExit=yes` timer issue without replacing the route script or rule set.

## Operating and checking the service

```sh
systemctl status xray.service
systemctl is-enabled xray.service
ss -lntp | grep ':8443'
xray run -test -config /usr/local/etc/xray/config.json
systemctl status tunneldeck-xray-policy.service tunneldeck-ru-route.timer
ip rule show
ip route show table 167
```

Both Xray units run as the unprivileged `xray` user with systemd filesystem and capability restrictions. They write warning-level diagnostics to the journal and have no access log. Server configs are mode `0640`, owned by `root:xray`. The pre-deployment and XHTTP rollback snapshot is root-only at `/root/tunneldeck-backups/reality-20261023-xhttp`; the earlier installation snapshot remains at `/root/tunneldeck-backups/reality-20261021-1520`.

## Client profiles

This checkout is a macOS infrastructure dashboard, not a VPN client, and it has no Android TunnelDeck app or Network Extension. The UI now reports the server-side Xray unit and listener separately from route policy and tunnel state; it does not create or activate a full-device tunnel.

- Mac test: the protected `mac-client.json` uses the official Xray arm64 core and exposes a local SOCKS5 listener at `127.0.0.1:10808`. This was used for the real transfer tests in `REALITY_TEST_REPORT.md`.
- XHTTP fallback: the protected `mac-xhttp-client.json` uses Xray-core `26.10.21` and a local SOCKS5 listener at `127.0.0.1:10888`. The corresponding device URIs stay in the protected `mac-xhttp.vless.txt` and `android-xhttp.vless.txt` files; never put these files in Git or support bundles.
- Caddy TLS XHTTP: the protected `mac-xhttp-tls-client.json` uses a local SOCKS5 listener at `127.0.0.1:10889`; the corresponding Mac and Android URI files and Samsung QR image are stored under `~/.config/tunneldeck/reality/`. The TLS profile was imported into Happ Plus and its client ping test succeeded. It has not been made the selected/connected system VPN profile.
- Samsung: import the URI in the protected `android.vless.txt` profile into an Android client that supports VLESS, REALITY, and Vision. Use only the official client distribution. The Android device and mobile networks have not been tested here. Do not paste the URI into chat or commit it.
- Generate a fresh UUID for any additional device and add only its UUID/email to the server's `clients` list. Do not reuse a device UUID.

The profiles are single-device manual configurations. The server has three independently monitored entries: Vision + REALITY on 8443, XHTTP + REALITY on 2053, and XHTTP through Caddy's normal TLS on 443. Client failover is manual. TunnelDeck does not control full-device VPN state, and none of these server entries means the home Xiaomi or Archer has begun using REALITY.

## Source references

- [Xray REALITY transport](https://xtls.github.io/en/config/transports/reality.html)
- [Xray VLESS inbound and Vision flow](https://xtls.github.io/en/config/inbounds/vless.html)
- [Xray transport settings](https://xtls.github.io/en/config/transport.html)
- [Official Xray-core releases](https://github.com/XTLS/Xray-core/releases)
- [v2rayNG releases](https://github.com/2dust/v2rayNG/releases)
