## Service Manager


- MacOS
  - [x] launchctl
- Windows
  - [x] Sc - [https://learn.microsoft.com/en-us/sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))
- Linux
  - [x] Systemd - https://en.wikipedia.org/wiki/Systemd
  - [ ] OpenRc - https://en.wikipedia.org/wiki/OpenRC
  - [ ] Procd(OpenWrt) - https://openwrt.org/docs/techref/procd



## Configurations

- [x] `server-name`

- [x] `bind`

- [x] `bind-tcp`

- [x] `bind-tls`

- [x] `bind-cert-file`

- [x] `bind-cert-key`

- [x] `cache-size`

- [x] `cache-persist`

- [x] `cache-file`

- [x] `tcp-idle-time`

- [x] `rr-ttl-min`

- [x] `tt-ttl-max`

- [x] `tt-ttl-replay-max`

- [x] `local-ttl`

- [x] `max-reply-ip-num`

- [x] Log

  - [x] `log-level`
  - [x] `log-size`
  - [x] `log-num`
  - [x] `log-file-mode`
  - [ ] `log-console`

- [x] Audit

  - [x] `audit-enable`
  - [x] `audit-file`
  - [x] `audit-size`
  - [x] `audit-num`
  - [x] `audit-file-mode`
  - [ ] `audit-console`

- [x] `conf-file`

- [x] `server`

- [x] `server-tcp`

- [x] `server-tls`

- [x] `server-https`

- [x] `proxy-server`

  - [x] `socks5`
  - [ ] `http`

- [x] `speed-check-mode`

- [x] `response-mode`

- [x] `address`

- [ ] `cname`

- [ ] `dns64`

- [ ] `edns-client-subnet`

- [x] `nameserver`

- [ ] `ipset`

- [ ] `ipset-timeout`

- [ ] `ipset-no-speed`

- [ ] `nftset`

- [ ] `nftset-timeout`

- [ ] `nftset-no-speed`

- [ ] `nftset-debug`

- [x] `domain-rule(s)`

- [x] `domain-set`

- [x] `bogus-nxdomain`

- [x] `ignore-ip`

- [x] `whitelist-ip`

- [x] `blacklist-ip`

- [x] `force-AAAA-SOA`

- [x] `force-qtype-SOA`

- [x] `prefetch-domain`

- [x] `dnsmasq-lease-file`

- [x] `serve-expired`

- [x] `serve-expired-ttl`

- [x] `serve-expired-reply-ttl`

- [ ] `serve-expired-prefetch-time`

- [ ] `dualstack-ip-selection`

- [ ] `dualstack-ip-selection-threshold`

- [x] `user`

  Linux only.

- [x] `ca-file`

- [x] `ca-path`