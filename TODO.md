# TO-DO LIST

The functions that have been completed are not guaranteed to be completely problem-free, as they have not been rigorously tested.


## Service Manager


- `MacOS`
  - [x] `launchctl`
  - [x] `homebrew`（via `--features homebrew`）
- Windows
  - [x] Sc - [https://learn.microsoft.com/en-us/sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))
- Linux
  - [x] `Systemd` - [https://en.wikipedia.org/wiki/Systemd](https://en.wikipedia.org/wiki/Systemd)
  - [ ] `OpenRc` - [https://en.wikipedia.org/wiki/OpenRC](https://en.wikipedia.org/wiki/OpenRC)
  - [ ] `Procd`(`OpenWrt`) - [https://openwrt.org/docs/techref/procd](https://openwrt.org/docs/techref/procd)



## Configurations

- [x] `server-name` 

  DNS server name，lookup by `dig whoami ptr`

- [x] `num-worker ` （Draft）

   The number of worker threads

- [x] `bind` 

  UDP mode DNS listening port number

- [x] `bind-tcp`

  TCP mode DNS listening port number

- [x] `bind-tls`

   DOT mode DNS listening port number

- [x] `bind-cert-file`

  SSL Certificate file path

- [x] `bind-cert-key`

  SSL Certificate key file path

- [ ] `bind-cert-key-pass`

  SSL Certificate key file password

- [x] `cache-size`

  Domain name result cache number

- [x] `cache-persist`

  enable persist cache

- [x] `cache-file`

  cache persist file

- [x] `tcp-idle-time`

  TCP connection idle timeout

- [x] `rr-ttl`

  Domain name TTL

- [x] `rr-ttl-min`

  Domain name Minimum TTL

- [x] `tt-ttl-max`

  Domain name Maximum TTL

- [x] `tt-ttl-replay-max`

  Domain name Minimum Reply TTL

- [x] `local-ttl`

  ttl for address and host

- [x] `max-reply-ip-num`

  Maximum number of IPs returned to the client

- [x] Log

  - [x] `log-level`

  - [x] `log-size`

  - [x] `log-num`

    archived log number

  - [x] `log-file-mode`

    archived log file mode

  - [ ] `log-console`

     enable output log to console

- [x] Audit

  - [x] `audit-enable`

  - [x] `audit-file`

    - [x] log

    - [x] csv

      enable by `.csv` file extension.

  - [x] `audit-size`

  - [x] `audit-num`

    archived audit log number

  - [x] `audit-file-mode`

    archived audit log file mode

  - [ ] `audit-console`

    enable output audit log to console

- [x] `conf-file`

  additional conf file

- [x] `server`

   Upstream UDP DNS server

- [x] `server-tcp`

  Upstream TCP DNS server

- [x] `server-tls`

  Upstream TLS DNS server

- [x] `server-https`

  Upstream HTTPS DNS server

- [ ] `server-quic`

   Upstream QUIC DNS server

- [x] `proxy-server`

  proxy server

  - [x] `socks5`
  - [ ] `http`

- [x] `speed-check-mode

- [x] `response-mode`

  First query response mode

- [x] `address`

  Domain IP address

- [x] `cname`

  set cname to domain

- [ ] `dns64`

  dns64 translation

- [x] `edns-client-subnet`

  DNS ECS

- [x] `nameserver`

  To query domain with specific server group

- [ ] `ipset`

   Domain IPSet

- [ ] `ipset-timeout`

  ipset timeout enable

- [ ] `ipset-no-speed`

  When speed check fails, set the ip address of the domain name to the ipset

- [ ] `nftset`

  Domain nftset

- [ ] `nftset-timeout`

  nftset timeout enable

- [ ] `nftset-no-speed`

  When speed check fails, set the ip address of the domain name to the nftset

- [ ] `nftset-debug`

  nftset debug enable

- [x] `domain-rule(s)`

  set domain rules

- [x] `domain-set`

  collection of domains

- [x] `bogus-nxdomain`

  bogus IP address

- [x] `ignore-ip`

  ignore ip address

- [x] `whitelist-ip`

  ip whitelist

- [x] `blacklist-ip`

  ip blacklist

- [x] `force-AAAA-SOA`

  force AAAA query return SOA

- [x] `force-qtype-SOA`

  force specific qtype return SOA

- [x] `prefetch-domain`

  domain prefetch feature

- [x] `dnsmasq-lease-file`

  Support reading dnsmasq dhcp file to resolve local hostname

- [x] `serve-expired`

  Cache serve expired feature

- [x] `serve-expired-ttl`

  Cache serve expired limit TTL

- [x] `serve-expired-reply-ttl`

  TTL value to use when replying with expired data

- [ ] `serve-expired-prefetch-time`

  Prefetch time when serve expired

- [ ] `dualstack-ip-selection`

  Dualstack ip selection

- [ ] `dualstack-ip-selection-threshold`

  Dualstack ip select thresholds

- [x] `user`

  run as user(Linux only.)

- [x] `ca-file`

  certificate file

- [x] `ca-path`

  certificates path
