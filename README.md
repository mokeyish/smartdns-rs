# SmartDNS-rs

![Test](https://github.com/mokeyish/smartdns-rs/actions/workflows/test.yml/badge.svg?branch=main)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/mokeyish/smartdns-rs?display_name=tag&include_prereleases)

[English](https://github.com/mokeyish/smartdns-rs/blob/main/README_en-US.md) | 中文

SmartDNS-rs 🐋 一个是受 [C 语言版 smartdns](https://github.com/pymumu/smartdns)  启发而开发的，并与其配置兼容的运行在本地的跨平台 DNS 服务器，
它接受来自本地客户端的 DNS 查询请求，然后从多个上游 DNS 服务器获取 DNS 查询结果，并将访问速度最快的结果返回给客户端，
以此提高网络访问速度。 SmartDNS 同时支持指定特定域名 IP 地址，并高性匹配，可达到过滤广告的效果。

说明：C 语言版的 [smartdns](https://github.com/pymumu/smartdns) 功能非常的不错，但由于其仅支持 **Linux**，而对 **MacOS、Windows** 只能通过 Docker 或 WSL 支持。因此，才想开发一个 rust 版的 SmartDNS，支持编译到 Windows、MacOS、Linux 以及 Android 的 Termux 环境运行，并与其配置兼容。

---

**目前正在开发中，请勿用于生产环境。**


## 构建与运行

打开的你的命令行界面,执行如下命令：

```shell
git clone https://github.com/mokeyish/smartdns-rs.git
cd smartdns-rs

# 编译
cargo build --release

# 查看命令帮助
./target/release/smartdns help

# 运行
sudo ./target/release/smartdns run -c ./etc/smartdns/smartdns.conf
```



## 安装为系统服务

到[此处](https://github.com/mokeyish/smartdns-rs/releases)下载编译好的程序包，解压执行如下命令进行服务管理。

可使用如下命令查看服务管理命令的帮助：

```shell
./smartdns service help
```

- MacOS
  - [x] launchctl
- Windows
  - [x] Sc - [https://learn.microsoft.com/en-us/sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))
- Linux
  - [x] Systemd - https://en.wikipedia.org/wiki/Systemd
  - [ ] OpenRc - https://en.wikipedia.org/wiki/OpenRC
  - [x] Procd(OpenWrt) - https://openwrt.org/docs/techref/procd



### Linux / MacOS


1. 安装服务

   ```shell
   sudo ./smartdns service install
   ```

2. 启动服务

   ```shell
   sudo ./smartdns service start
   ```

3. 关闭服务

   ```shell
   sudo ./smartdns service stop
   ```

4. 卸载服务

   ```shell
   sudo ./smartdns service uninstall
   ```

### Windows

以管理员身份运行  cmd 或 powershell 执行下面的命令。

1. 安装服务

   ```powershell
   ./smartdns service install
   ```

2. 启动服务

   ```powershell
   ./smartdns service start
   ```

3. 关闭服务

   ```powershell
   ./smartdns service stop
   ```

4. 卸载服务

   ```powershell
   ./smartdns service uninstall
   ```


## 配置文件说明

功能覆盖状态（更多详细的配置请参考 [这里](https://github.com/pymumu/smartdns#%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6%E8%AF%B4%E6%98%8E)）

- :white_check_mark: 可用
- :construction: 开发中

| 键名                             | 功能说明                                   | 状态               | 默认值                                                       | 可用值/要求                                                  | 举例                                                         |
| :------------------------------- | :----------------------------------------- | ------------------ | :----------------------------------------------------------- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| server-name                      | DNS 服务器名称                             | :white_check_mark: | 操作系统主机名 / smartdns                                    | 符合主机名规格的字符串                                       | server-name smartdns                                         |
| bind                             | DNS 监听端口号                             | :white_check_mark: | [::]:53                                                      | 可绑定多个端口。<br>IP:PORT: 服务器 IP:端口号<br>[-group]: 请求时使用的 DNS 服务器组<br>[-no-rule-addr]：跳过 address 规则<br>[-no-rule-nameserver]：跳过 Nameserver 规则<br>[-no-rule-ipset]：跳过 ipset 和 nftset 规则<br>[-no-rule-soa]：跳过 SOA(#) 规则<br>[-no-dualstack-selection]：停用双栈测速<br>[-no-speed-check]：停用测速<br>[-no-cache]：停止缓存 | bind :53                                                     |
| bind-tcp                         | DNS TCP 监听端口号                         | :white_check_mark: | [::]:53                                                      | 可绑定多个端口。<br>IP:PORT: 服务器 IP:端口号<br>[-group]: 请求时使用的 DNS 服务器组<br>[-no-rule-addr]：跳过 address 规则<br>[-no-rule-nameserver]：跳过 nameserver 规则<br>[-no-rule-ipset]：跳过 ipset 和 nftset 规则。<br>[-no-rule-soa]：跳过 SOA(#) 规则<br>[-no-dualstack-selection]：停用双栈测速<br>[-no-speed-check]：停用测速<br>[-no-cache]：停止缓存 | bind-tcp :53                                                 |
| cache-size                       | 域名结果缓存个数                           | :white_check_mark: | 512                                                          | 大于等于 0 的数字                                            | cache-size 512                                               |
| cache-persist                    | 是否持久化缓存                             | :construction:     | 自动。<br>当 cache-file 所在的位置有超过 128 MB 的可用空间时启用，否则禁用。 | [yes\|no]                                                    | cache-persist yes                                            |
| cache-file                       | 缓存持久化文件路径                         | :construction:     | /tmp/smartdns.cache                                          | 合法路径字符串                                               | cache-file /tmp/smartdns.cache                               |
| tcp-idle-time                    | TCP 链接空闲超时时间                       | :construction:     | 120                                                          | 大于等于 0 的数字                                            | tcp-idle-time 120                                            |
| rr-ttl                           | 域名结果 TTL                               | :white_check_mark: | 远程查询结果                                                 | 大于 0 的数字                                                | rr-ttl 600                                                   |
| rr-ttl-min                       | 允许的最小 TTL 值                          | :white_check_mark: | 远程查询结果                                                 | 大于 0 的数字                                                | rr-ttl-min 60                                                |
| rr-ttl-max                       | 允许的最大 TTL 值                          | :white_check_mark: | 远程查询结果                                                 | 大于 0 的数字                                                | rr-ttl-max 600                                               |
| rr-ttl-reply-max                 | 允许返回给客户端的最大 TTL 值              | :construction:     | 远程查询结果                                                 | 大于 0 的数字                                                | rr-ttl-reply-max 60                                          |
| local-ttl                        | 本地HOST，address的TTL值                   | :construction:     | rr-ttl-min                                                   | 大于 0 的数字                                                | local-ttl  60                                                |
| max-reply-ip-num                 | 允许返回给客户的最大IP数量                 | :construction:     | IP数量                                                       | 大于 0 的数字                                                | max-reply-ip-num 1                                           |
| log-level                        | 设置日志级别                               | :white_check_mark:     | error                                                        | fatal、error、warn、notice、info 或 debug                    | log-level error                                              |
| log-file                         | 日志文件路径                               | :white_check_mark:     | /var/log/smartdns/smartdns.log                               | 合法路径字符串                                               | log-file /var/log/smartdns/smartdns.log                      |
| log-size                         | 日志大小                                   | :white_check_mark:     | 128K                                                         | 数字 + K、M 或 G                                             | log-size 128K                                                |
| log-num                          | 日志归档个数                               | :white_check_mark:     | 2                                                            | 大于等于 0 的数字                                            | log-num 2                                                    |
| audit-enable                     | 设置审计启用                               | :white_check_mark: | no                                                           | [yes\|no]                                                    | audit-enable yes                                             |
| audit-file                       | 审计文件路径                               | :white_check_mark: | /var/log/smartdns/smartdns-audit.log                         | 合法路径字符串，log 后缀可改成 csv                           | audit-file /var/log/smartdns/smartdns-audit.log              |
| audit-size                       | 审计大小                                   | :white_check_mark: | 128K                                                         | 数字 + K、M 或 G                                             | audit-size 128K                                              |
| audit-num                        | 审计归档个数                               | :white_check_mark: | 2                                                            | 大于等于 0 的数字                                            | audit-num 2                                                  |
| conf-file                        | 附加配置文件                               | :white_check_mark: | 无                                                           | 合法路径字符串                                               | conf-file /etc/smartdns/smartdns.more.conf                   |
| server                           | 上游 UDP DNS                               | :white_check_mark: | 无                                                           | 可重复。<br>[ip][:port]：服务器 IP:端口（可选）<br>[-blacklist-ip]：配置 IP 过滤结果。<br>[-whitelist-ip]：指定仅接受参数中配置的 IP 范围<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server 8.8.8.8:53 -blacklist-ip -group g1                    |
| server-tcp                       | 上游 TCP DNS                               | :white_check_mark: | 无                                                           | 可重复。<br>[ip][:port]：服务器 IP:端口（可选）<br>[-blacklist-ip]：配置 IP 过滤结果<br>[-whitelist-ip]：指定仅接受参数中配置的 IP 范围。<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server-tcp 8.8.8.8:53                                        |
| server-tls                       | 上游 TLS DNS                               | :white_check_mark: | 无                                                           | 可重复。<br>[ip][:port]：服务器 IP:端口（可选)<br>[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值，base64 编码的 sha256 SPKI pin 值<br>[-host-name]：TLS SNI 名称, 名称设置为-，表示停用SNI名称<br>[-tls-host-verify]：TLS 证书主机名校验<br> [-no-check-certificate]：跳过证书校验<br>[-blacklist-ip]：配置 IP 过滤结果<br>[-whitelist-ip]：仅接受参数中配置的 IP 范围<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server-tls 8.8.8.8:853                                       |
| server-https                     | 上游 HTTPS DNS                             | :white_check_mark: | 无                                                           | 可重复。<br>https://[host][:port]/path：服务器 IP:端口（可选）<br>[-spki-pin [sha256-pin]]：TLS 合法性校验 SPKI 值，base64 编码的 sha256 SPKI pin 值<br>[-host-name]：TLS SNI 名称<br>[-http-host]：http 协议头主机名<br>[-tls-host-verify]：TLS 证书主机名校验<br> [-no-check-certificate]：跳过证书校验<br>[-blacklist-ip]：配置 IP 过滤结果<br>[-whitelist-ip]：仅接受参数中配置的 IP 范围。<br>[-group [group] ...]：DNS 服务器所属组，比如 office 和 foreign，和 nameserver 配套使用<br>[-exclude-default-group]：将 DNS 服务器从默认组中排除 | server-https https://cloudflare-dns.com/dns-query            |
| speed-check-mode                 | 测速模式选择                               | :construction:     | 无                                                           | [ping\|tcp:[80]\|none]                                       | speed-check-mode ping,tcp:80,tcp:443                         |
| response-mode                    | 首次查询响应模式                           | :construction:     | first-ping                                                   | 模式：[fisrt-ping\|fastest-ip\|fastest-response]<br> [first-ping]: 最快ping响应地址模式，DNS上游最快查询时延+ping时延最短，查询等待与链接体验最佳;<br>[fastest-ip]: 最快IP地址模式，查询到的所有IP地址中ping最短的IP。需等待IP测速; <br>[fastest-response]: 最快响应的DNS结果，DNS查询等待时间最短，返回的IP地址可能不是最快。 | response-mode first-ping                                     |
| address                          | 指定域名 IP 地址                           | :white_check_mark: | 无                                                           | address /domain/[ip\|-\|-4\|-6\|#\|#4\|#6] <br>- 表示忽略 <br># 表示返回 SOA <br>4 表示 IPv4 <br>6 表示 IPv6 | address /www.example.com/1.2.3.4                             |
| nameserver                       | 指定域名使用 server 组解析                 | :white_check_mark: | 无                                                           | nameserver /domain/[group\|-], group 为组名，- 表示忽略此规则，配套 server 中的 -group 参数使用 | nameserver /www.example.com/office                           |
| ipset                            | 域名 ipset                                 | :construction:     | 无                                                           | ipset /domain/[ipset\|-\|#[4\|6]:[ipset\|-][,#[4\|6]:[ipset\|-]]]，-表示忽略 | ipset /www.example.com/#4:dns4,#6:-                          |
| ipset-timeout                    | 设置 ipset 超时功能启用                    | :construction:     | no                                                           | [yes\|no]                                                    | ipset-timeout yes                                            |
| nftset                           | 域名 nftset                                | :construction:     | 无                                                           | nftset /domain/[#4\|#6\|-]:[family#nftable#nftset\|-][,#[4\|6]:[family#nftable#nftset\|-]]]，-表示忽略；ipv4 地址的 family 只支持 inet 和 ip；ipv6 地址的 family 只支持 inet 和 ip6；由于 nft 限制，两种地址只能分开存放于两个 set 中。 | nftset /www.example.com/#4:inet#mytab#dns4,#6:-              |
| nftset-timeout                   | 设置 nftset 超时功能启用                   | :construction:     | no                                                           | [yes\|no]                                                    | nftset-timeout yes                                           |
| nftset-debug                     | 设置 nftset 调试功能启用                   | :construction:     | no                                                           | [yes\|no]                                                    | nftset-debug yes                                             |
| domain-rules                     | 设置域名规则                               |                    | 无                                                           | domain-rules /domain/ [-rules...]<br>[-c\|-speed-check-mode]：测速模式，参考 speed-check-mode 配置<br>[-a\|-address]：参考 address 配置<br>[-n\|-nameserver]：参考 nameserver 配置<br>[-p\|-ipset]：参考ipset配置<br>[-t\|-nftset]：参考nftset配置<br>[-d\|-dualstack-ip-selection]：参考 dualstack-ip-selection | domain-rules /www.example.com/ -speed-check-mode none        |
| domain-set                       | 设置域名集合                               | :white_check_mark: | 无                                                           | domain-set [options...]<br>[-n\|-name]：域名集合名称 <br>[-t\|-type]：域名集合类型，当前仅支持list，格式为域名列表，一行一个域名。<br>[-f\|-file]：域名集合文件路径。<br> 选项需要配合address, nameserver, ipset, nftset等需要指定域名的地方使用，使用方式为 /domain-set:[name]/ | domain-set -name set -type list -file /path/to/list <br> address /domain-set:set/1.2.4.8 |
| bogus-nxdomain                   | 假冒 IP 地址过滤                           | :construction:     | 无                                                           | [ip/subnet]，可重复                                          | bogus-nxdomain 1.2.3.4/16                                    |
| ignore-ip                        | 忽略 IP 地址                               | :construction:     | 无                                                           | [ip/subnet]，可重复                                          | ignore-ip 1.2.3.4/16                                         |
| whitelist-ip                     | 白名单 IP 地址                             | :white_check_mark:     | 无                                                           | [ip/subnet]，可重复                                          | whitelist-ip 1.2.3.4/16                                      |
| blacklist-ip                     | 黑名单 IP 地址                             | :white_check_mark:     | 无                                                           | [ip/subnet]，可重复                                          | blacklist-ip 1.2.3.4/16                                      |
| force-AAAA-SOA                   | 强制 AAAA 地址返回 SOA                     | :construction:     | no                                                           | [yes\|no]                                                    | force-AAAA-SOA yes                                           |
| force-qtype-SOA                  | 强制指定 qtype 返回 SOA                    | :construction:     | qtype id                                                     | [<qtypeid> \| ...]                                           | force-qtype-SOA 65 28                                        |
| prefetch-domain                  | 域名预先获取功能                           | :white_check_mark: | no                                                           | [yes\|no]                                                    | prefetch-domain yes                                          |
| dnsmasq-lease-file               | 支持读取dnsmasq dhcp文件解析本地主机名功能 | :construction:     | 无                                                           | dnsmasq dhcp lease文件路径                                   | dnsmasq-lease-file /var/lib/misc/dnsmasq.leases              |
| serve-expired                    | 过期缓存服务功能                           | :construction:     | yes                                                          | [yes\|no]，开启此功能后，如果有请求时尝试回应 TTL 为 0 的过期记录，并发查询记录，以避免查询等待 |                                                              |
| serve-expired-ttl                | 过期缓存服务最长超时时间                   | :construction:     | 0                                                            | 秒，0 表示停用超时，大于 0 表示指定的超时的秒数              | serve-expired-ttl 0                                          |
| serve-expired-reply-ttl          | 回应的过期缓存 TTL                         | :construction:     | 5                                                            | 秒，0 表示停用超时，大于 0 表示指定的超时的秒数              | serve-expired-reply-ttl 30                                   |
| dualstack-ip-selection           | 双栈 IP 优选                               | :construction:     | yes                                                          | [yes\|no]                                                    | dualstack-ip-selection yes                                   |
| dualstack-ip-selection-threshold | 双栈 IP 优选阈值                           | :construction:     | 15ms                                                         | 单位为毫秒（ms）                                             | dualstack-ip-selection-threshold [0-1000]                    |
| user                             | 进程运行用户                               | :white_check_mark:     | root                                                         | user [username]                                              | user nobody                                                  |
| ca-file                          | 证书文件                                   | :white_check_mark:     | /etc/ssl/certs/ca-certificates.crt                           | 合法路径字符串                                               | ca-file /etc/ssl/certs/ca-certificates.crt                   |
| ca-path                          | 证书文件路径                               | :white_check_mark:     | /etc/ssl/certs                                               | 合法路径字符串                                               | ca-path /etc/ssl/certs                                       |

## 其他

待补充


## 鸣谢!!!

这个软件的诞生,少不了它们:

- [Trust-DNS](https://github.com/bluejekyll/trust-dns)
- [SmartDNS](https://github.com/pymumu/smartdns)



## 开源声明

本软件包含来自 https://github.com/bluejekyll/trust-dns 的代码, 其许可是下列二选一


- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)


其余代码则是

- GPL-3.0 license (LICENSE-GPL-3.0 or https://opensource.org/licenses/GPL-3.0)
