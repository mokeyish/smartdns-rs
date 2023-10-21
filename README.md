# SmartDNS-rs

![Test](https://github.com/mokeyish/smartdns-rs/actions/workflows/test.yml/badge.svg?branch=main)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/mokeyish/smartdns-rs?display_name=tag&include_prereleases)](https://github.com/mokeyish/smartdns-rs/releases)
![OS](https://img.shields.io/badge/os-Windows%20%7C%20MacOS%20%7C%20Linux-blue)

[Docs](https://pymumu.github.io/smartdns/en/) • [Discord](https://discord.gg/SDhQSA72)

English | [中文](https://github.com/mokeyish/smartdns-rs/blob/main/README_zh-CN.md)

SmartDNS-rs 🐋 is a local DNS server imspired by [C SmartDNS](https://github.com/pymumu/smartdns) to accepts DNS query requests from local clients, obtains DNS query results from multiple upstream DNS servers, and returns the fastest access results to clients. Avoiding DNS pollution and improving network access speed, supports high-performance ad filtering.



## Features

- **Multiple upstream DNS servers**

  Supports configuring multiple upstream DNS servers and query at the same  time.the query will not be affected, Even if there is a DNS server  exception.

- **Return the fastest IP address**

  Supports finding the fastest access IP address from the IP address list  of the domain name and returning it to the client to avoid DNS pollution and improve network access speed.

- **Support for multiple query protocols**

  Supports UDP, TCP, DoT(DNS over TLS), DoH(DNS over HTTPS) queries and  service, and non-53 port queries, effectively avoiding DNS pollution and protect privacy, and support query DNS over socks5, http proxy.

- **Domain IP address specification**

  Supports configuring IP address of specific domain to achieve the effect of advertising filtering, and avoid malicious websites.

- **DNS domain forwarding**

  Supports DNS forwarding, ipset and nftables. Support setting the domain result to ipset and nftset set when speed check fails.

- **Windows / MacOS / Linux multi-platform support**

  Supports installing as a service and running it at startup.

- **Support IPV4, IPV6 dual stack**

  Supports IPV4, IPV6 network, support query A, AAAA record, dual-stack IP selection, and filter IPV6 AAAA record.

- **DNS64**

  Supports DNS64 translation.

- **High performance, low resource consumption**

  Tokio-based multi-threaded asynchronous I/O model; caches query  results; supports most-used domain name expired prefetching, query **'0'**  milliseconds, without eliminating the impact of DoH and DoT encryption.

Note: The C version of smartdns is very functional, but because it only supports **Linux**, while **MacOS and Windows** can only be supported through Docker or WSL. Therefore, I want to develop a rust version of SmartDNS that supports compiling to Windows, MacOS, Linux and Android Termux environment to run, and is compatible with its configuration.

---

**It is still under development, please do not use it in production environment, welcome to try and provide feedback.**

Please refer to [TODO](https://github.com/mokeyish/smartdns-rs/blob/main/TODO.md) for the function coverage



## Installing

- MacOS

  If you have installed [brew](https://brew.sh/), you can directly use the following command to install.

  ```shell
  brew update
  brew install smartdns
  ```

  Note: Listening on port 53 requires root permission, so `sudo` is required.

  The command `sudo smartdns service start` for `brew` installed `smartdns` is the same as `sudo brew services start smartdns`.

  If you don't have `brew` installed, just download the compiled program compression package and install it as below.

- Windows / Linux

  Go to [here](https://github.com/mokeyish/smartdns-rs/releases) to download the package and decompress it.

  1. Get help

     ```shell
     ./smartdns help
     ```

  2. Run as foreground, easy to check the running status

     ```shell
     ./smartdns run -c ./smartdns.conf -d
     ```

     - `-d` or `--debug` is enabled to print debug logs.

  3. Run as background service, run automatically at startup

     Get help of service management commands.

     ```shell
     ./smartdns service help
     ```

     *Note: Installed as a system service, administrator / root permissions are required.*

     *Service management is compatible with all systems, call [sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11)) on Windows; call `launchctl` or `brew` on MacOS; call `Systemd` or `OpenRc` on Linux.*

## Configuration

The following is the simplest example configuration

```conf
# Listen on local port 53
bind 127.0.0.1:53  

# Configure bootstrap-dns, if not configured, call the system_conf, 
# it is recommended to configure, so that it will be encrypted.
server https://1.1.1.1/dns-query  -bootstrap-dns -exclude-default-group
server https://8.8.8.8/dns-query  -bootstrap-dns -exclude-default-group

# Configure default upstream server
server https://cloudflare-dns/dns-query
server https://dns.quad9.net/dns-query
server https://dns.google/dns-query

# Configure the Office(Home) upstream server
server 192.168.1.1 -exclude-default-group -group office

# Domain names ending with ofc are forwarded to the office group for resolution
nameserver /ofc/office

# Set static IP for domain name
address /test.example.com/1.2.3.5

# Block Domains (Ad Blocking)
address /ads.example.com/#
```

For more advanced configurations, please refer to [here](https://github.com/pymumu/smartdns/blob/doc/en/docs/configuration.md) , and refer to [TODO](https://github.com/mokeyish/smartdns-rs/blob/main/TODO.md) for the function coverage.

## Building

Assuming you have installed [Rust](https://www.rust-lang.org/learn/get-started), then you can open the terminal and execute these commands:

```shell
git clone https://github.com/mokeyish/smartdns-rs.git
cd smartdns-rs

# build
cargo build --release

# print help
./target/release/smartdns --help

# run
sudo ./target/release/smartdns run -c ./etc/smartdns/smartdns.conf
```

## Acknowledgments !!!

This software wouldn't have been possible without:

- [Hickory DNS](https://github.com/hickory-dns/hickory-dns)
- [SmartDNS](https://github.com/pymumu/smartdns)

## License

This software contains codes from [https://github.com/hickory-dns/hickory-dns](https://github.com/hickory-dns/hickory-dns), which is licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
- MIT license (LICENSE-MIT or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

And other codes is licensed under

- GPL-3.0 license (LICENSE-GPL-3.0 or [https://opensource.org/licenses/GPL-3.0](https://opensource.org/licenses/GPL-3.0))

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the GPL-3.0 license, shall be licensed as above, without any additional terms or conditions.
