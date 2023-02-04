# SmartDNS-rs

![Test](https://github.com/mokeyish/smartdns-rs/actions/workflows/test.yml/badge.svg?branch=main)
![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/mokeyish/smartdns-rs?display_name=tag&include_prereleases)

English | [中文](https://github.com/mokeyish/smartdns-rs/blob/main/README.md)

A local DNS server imspired by [c smartdns](https://github.com/pymumu/smartdns) to accepts DNS query requests from local clients, obtains DNS query results from multiple upstream DNS servers, and returns the fastest access results to clients.
Avoiding DNS pollution and improving network access speed, supports high-performance ad filtering.

Note: The c version of smartdns is very functional, but because it only supports **Linux**, while **MacOS and Windows** can only be supported through Docker or WSL. Therefore, I want to develop a rust version of SmartDNS that supports compiling to Windows, MacOS, Linux and Android Termux environment to run, and is compatible with its configuration.

---

**Currently under development, please do not use in production environment.**

## Building

Open your terminal and execute these commands:

```shell
git clone https://github.com/mokeyish/smartdns-rs.git
cd smartdns-rs

# build
cargo build --release

# print help
cargo build --release

# run
sudo ./target/release/smartdns run -c ./etc/smartdns/smartdns.conf
```

## Installing as system service

Please download smartdns-rs from [here](https://github.com/mokeyish/smartdns-rs/releases). 
Unzip and execute the following command for service management


You can use the following command to view the help of service management commands：

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
  - [ ] Procd(OpenWrt) - https://openwrt.org/docs/techref/procd

### Linux / MacOS

1. Install service

   ```shell
   sudo ./smartdns service install
   ```

2. Start service

   ```shell
   sudo ./smartdns service start
   ```

3. Stop service

   ```shell
   sudo ./smartdns service stop
   ```

4. Uninstall service

   ```shell
   sudo ./smartdns service uninstall
   ```

### Windows

Run cmd or powershell as administrator to execute the command below.

1. Install service

   ```powershell
   ./smartdns service install
   ```

2. Start service

   ```powershell
   ./smartdns service start
   ```

3. Stop service

   ```powershell
   ./smartdns service stop
   ```

4. Uninstall service

   ```powershell
   ./smartdns service uninstall
   ```

## Configuration parameter

Please refer to [here](https://github.com/pymumu/smartdns/blob/master/ReadMe_en.md#configuration-parameter) for configuration.


## Others

TODO...

## Acknowledgments !!!  

This software wouldn't have been possible without:

- [Trust-DNS](https://github.com/bluejekyll/trust-dns)
- [SmartDNS](https://github.com/pymumu/smartdns)



## License

This software contains codes from https://github.com/bluejekyll/trust-dns, which is licensed under either of


- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)


And other codes is licensed under

- GPL-3.0 license (LICENSE-GPL-3.0 or https://opensource.org/licenses/GPL-3.0)
