# SmartDNS-rs

![Test](https://github.com/mokeyish/smartdns-rs/actions/workflows/test.yml/badge.svg?branch=main)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/mokeyish/smartdns-rs?display_name=tag&include_prereleases)](https://github.com/mokeyish/smartdns-rs/releases)

[Docs](https://pymumu.github.io/smartdns/en/) • [Discord](https://discord.gg/SDhQSA72)

English | [中文](https://github.com/mokeyish/smartdns-rs/blob/main/README_zh-CN.md)

SmartDNS-rs 🐋 is a local DNS server imspired by [C smartdns](https://github.com/pymumu/smartdns) to accepts DNS query requests from local clients, obtains DNS query results from multiple upstream DNS servers, and returns the fastest access results to clients.
Avoiding DNS pollution and improving network access speed, supports high-performance ad filtering.

Note: The C version of smartdns is very functional, but because it only supports **Linux**, while **MacOS and Windows** can only be supported through Docker or WSL. Therefore, I want to develop a rust version of SmartDNS that supports compiling to Windows, MacOS, Linux and Android Termux environment to run, and is compatible with its configuration.

---

**It is still under development, please do not use it in production environment, welcome to try and provide feedback.**

Please refer to [TODO](https://github.com/mokeyish/smartdns-rs/blob/main/TODO.md) for the function coverage

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

## Installing 

Building from source code might be troublesome, you can download the compiled package [here](https://github.com/mokeyish/smartdns-rs/releases) and unzip it.

- Run as foreground

  ```shell
  ./smartdns run -c ./smartdns.conf -d
  ```

  - `-d` or `--debug` is enabled to print debug logs 

- Install as a service and run automatically in the background at startup

  To install as a system service, you need administrator privileges. (MacOS users can use the Brew command to install, `brew install smartdns`) 

  - Install service

    ```shell
    ./smartdns service install
    ```

  - Start service

    ```shell
    ./smartdns service start
    ```

  - Stop service

    ```shell
    ./smartdns service stop
    ```

  - Uninstall service

    ```shell
    ./smartdns service uninstall -p
    ```

    - `-p` or `--purge` will delete the configuration file along with it.

  You can use the following command to view the help of service management commands：

  ```shell'
  ./smartdns service help
  ```

## Configuration parameter

Please refer to [here](https://github.com/pymumu/smartdns/blob/doc/en/docs/configuration.md) for configuration, and refer to [TODO](https://github.com/mokeyish/smartdns-rs/blob/main/TODO.md) for the function coverage.

## Acknowledgments !!! 

This software wouldn't have been possible without:

- [Trust-DNS](https://github.com/bluejekyll/trust-dns)
- [SmartDNS](https://github.com/pymumu/smartdns)

## License

This software contains codes from [](https://github.com/bluejekyll/trust-dns), which is licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
- MIT license (LICENSE-MIT or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

And other codes is licensed under

- GPL-3.0 license (LICENSE-GPL-3.0 or [https://opensource.org/licenses/GPL-3.0](https://opensource.org/licenses/GPL-3.0))
