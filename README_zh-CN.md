# SmartDNS-rs

![Test](https://github.com/mokeyish/smartdns-rs/actions/workflows/test.yml/badge.svg?branch=main)
[![Crates.io Version](https://img.shields.io/crates/v/smartdns.svg)](https://crates.io/crates/smartdns)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/mokeyish/smartdns-rs?display_name=tag&include_prereleases)](https://github.com/mokeyish/smartdns-rs/releases)
[![homebrew version](https://img.shields.io/homebrew/v/smartdns)](https://formulae.brew.sh/formula/smartdns)
![OS](https://img.shields.io/badge/os-Windows%20%7C%20MacOS%20%7C%20Linux-blue)

[Docs](https://pymumu.github.io/smartdns/) •

[English](https://github.com/mokeyish/smartdns-rs/blob/main/README.md) | 中文

SmartDNS-rs 🐋 一个是受 [C 语言版 SmartDNS](https://github.com/pymumu/smartdns)  启发而开发的，并与其配置兼容的运行在本地的跨平台 DNS 服务器，
它接受来自本地客户端的 DNS 查询请求，然后从多个上游 DNS 服务器获取 DNS 查询结果，并将访问速度最快的结果返回给客户端，
以此提高网络访问速度。 SmartDNS 同时支持指定特定域名 IP 地址，并高性匹配，可达到过滤广告的效果。

## 特性

- **多 DNS 上游服务器**

  支持配置多个上游 DNS 服务器，并同时进行查询，即使其中有 DNS 服务器异常，也不会影响查询。

- **返回最快 IP 地址**

  支持从域名所属 IP 地址列表中查找到访问速度最快的 IP 地址，并返回给客户端，提高网络访问速度。

- **支持多种查询协议**

  支持 UDP、TCP、DoT、DoQ、DoH 和 DoH3 查询及服务，以及非 53 端口查询；支持通过socks5，HTTP代理查询。

- **特定域名 IP 地址指定**

  支持指定域名的 IP 地址，达到广告过滤效果、避免恶意网站的效果。

- **域名分流**

  支持域名分流，不同类型的域名向不同的 DNS 服务器查询

- **Windows / MacOS / Linux 多平台支持**

  支持安装成服务开启自启动。

- **支持 IPv4、IPv6 双栈**

  支持 IPv4 和 IPV 6网络，支持查询 A 和 AAAA 记录，支持双栈 IP 速度优化，并支持完全禁用 IPv6 AAAA 解析。

- **支持DNS64**

  支持DNS64转换。

- **高性能、占用资源少**

  [Tokio](https://tokio.rs/) 加持的多线程异步 IO 模式；缓存查询结果；支持常用域名过期预读取，查询 **“0”** 毫秒，免除 DoH、DoT 加密带来的速度影响。

*说明：C 语言版的 [smartdns](https://github.com/pymumu/smartdns) 功能非常的不错，但由于其仅支持 **Linux**，而对 **MacOS、Windows** 只能通过 Docker 或 WSL 支持。因此，才想开发一个 rust 版的 SmartDNS，支持编译到 Windows、MacOS、Linux 以及 Android 的 Termux 环境运行，并与其配置兼容。*

---

**目前仍在开发中，请勿用于生产环境，欢迎试用并提供反馈。**

请参考 [TODO](https://github.com/mokeyish/smartdns-rs/blob/main/TODO.md) 查看功能覆盖情况。 



## 安装

*每日构建的版本可以在[这](https://github.com/mokeyish/smartdns-rs/actions/workflows/nightly.yml)找到。*

- MacOS

  如果你有安装 [brew](https://brew.sh/) ，可以直接用下面的命令进行安装。

  ```shell
  brew update
  brew install smartdns
  ```

  注意：监听 53 端口需要 `root` 权限，因此需要 `sudo`。

  `brew` 安装的 `smartdns` 的命令 `sudo smartdns service start` 与 `sudo brew services start smartdns` 一样。

  如果没有安装 `brew`，就与下面一样，下载编译好的程序压缩包进行安装。

- Windows / Linux

  到[此处](https://github.com/mokeyish/smartdns-rs/releases)下载程序包，并解压。

  1. 查看帮助

     ```shell
     ./smartdns --help
     ```

  2. 前台运行，方便查看运行状况

     ```shell
     ./smartdns run -c ./smartdns.conf -v
     ```

     - `-v` 是开启打印调试日志

  3. 后台服务运行，开机自动运行

     查看服务管理命令：

     ```shell
     ./smartdns service --help
     ```

     *注意：安装成系统服务，需要 administrator / root 权限。*

     *服务管理是各系统兼容的，window 下调用 [sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))；MacOS 下调用 `launchctl` 或者 `brew`；Linux 下调用 `Systemd`  或 `OpenRc`。*

## 配置文件

下面是一份最简单的示例配置

```conf
# 在本地 53 端口监听
bind 127.0.0.1:53  

# 配置 bootstrap-dns，如不配置则调用系统的，建议配置，这样就加密了。
server https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group

# 配置默认上游服务器
server https://dns.alidns.com/dns-query
server https://doh.pub/dns-query

# 配置公司（家里）上游服务器
server 192.168.1.1 -exclude-default-group -group office

# 以 ofc 结尾的域名转发至 office 分组进行解析
nameserver /ofc/office

# 设置域名的静态 IP
address /test.example.com/1.2.3.5

# 屏蔽域名（广告屏蔽）
address /ads.example.com/#

# 以下特性在[C 语言版 SmartDNS](https://github.com/pymumu/smartdns) 尚未支持，仅适用于SmartDNS-rs
# 使用 DoH3
server-h3 223.5.5.5

# 使用 DoQ
server-quic 223.5.5.5
```



更多高级的配置请参考 [这里](https://github.com/pymumu/smartdns/blob/doc/docs/configuration.md)

## 使用 `dig` 查询内置诊断信息

SmartDNS-rs 支持通过 `CHAOS TXT` 查询内置诊断字段。

```shell
# 服务器名
dig @127.0.0.1 CH TXT hostname.bind +short

# 服务器版本
dig @127.0.0.1 CH TXT version.bind +short

# 服务端看到的客户端源 IP
dig @127.0.0.1 CH TXT whoami.bind +short

# 客户端 MAC（局域网且服务端 ARP 表可见）
dig @127.0.0.1 CH TXT whoami.mac.bind +short

# 聚合信息
dig @127.0.0.1 CH TXT smartdns.info.bind +short

# JSON 输出（单条 TXT）
dig @127.0.0.1 CH TXT smartdns.info.json.bind +short

# 多条 TXT 输出（每条一个键值）
dig @127.0.0.1 CH TXT smartdns.info.records.bind +short

# SmartDNS 自有短名称（去掉 `.bind`）
dig @127.0.0.1 CH TXT version +short

# SmartDNS 自有 JSON / 多记录别名
dig @127.0.0.1 CH TXT json.smartdns +short
dig @127.0.0.1 CH TXT records.smartdns +short
```

`whoami.mac.bind` 依赖服务端主机对客户端的 ARP 可见性（通常要求同二层网络，Linux 下可用）。

## 从源码构建与运行

假设你已经安装了 [Rust](https://www.rust-lang.org/learn/get-started)，那么你可以打开命令行界面，执行如下命令：

```shell
git clone https://github.com/mokeyish/smartdns-rs.git
cd smartdns-rs

# 安装 https://github.com/casey/just
cargo install just

# 编译
just build --release

# 查看命令帮助
./target/release/smartdns help

# 运行
sudo ./target/release/smartdns run -c ./etc/smartdns/smartdns.conf
```

对于交叉编译，推荐使用[cross](https://github.com/cross-rs/cross)（依赖Docker）

## 鸣谢!!!

这个软件的诞生,少不了它们:

- [Hickory DNS](https://github.com/hickory-dns/hickory-dns)
- [SmartDNS](https://github.com/pymumu/smartdns)

## 开源声明

本软件包含来自 [https://github.com/hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns) 的代码, 其许可是下列二选一

- Apache License, Version 2.0, (LICENSE-APACHE or [](http://www.apache.org/licenses/LICENSE-2.0))
- MIT license (LICENSE-MIT or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

其余代码则是

- GPL-3.0 license (LICENSE-GPL-3.0 or [https://opensource.org/licenses/GPL-3.0](https://opensource.org/licenses/GPL-3.0))

## 贡献

除非您另有明确说明，否则您有意提交以包含在作品中的任何贡献，如 GPL-3.0 许可中所定义，应按上述方式获得许可，没有任何附加条款或条件。
