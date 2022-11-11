# SmartDNS-rs


[English](https://github.com/mokeyish/smartdns-rs/blob/master/README.md) | 中文

SmartDNS-rs 一个是受 [c 版 smartdns](https://github.com/pymumu/smartdns)  启发而开发的，并与其配置兼容的运行在本地的 DNS 服务器，
它接受来自本地客户端的 DNS 查询请求，然后从多个上游 DNS 服务器获取 DNS 查询结果，并将访问速度最快的结果返回给客户端，
以此提高网络访问速度。 SmartDNS 同时支持指定特定域名 IP 地址，并高性匹配，可达到过滤广告的效果。

说明：c 版 [smartdns](https://github.com/pymumu/smartdns) 功能非常的不错，但由于其仅支持 **Linux**，而对 **MacOS、Windows** 只能通过 Docker 或 WSL 支持。因此，才想开发一个 rust 版的 SmartDNS，支持编译到 Windows、MacOS、Linux 以及 Android 的 Termux 环境运行，并与其配置兼容。

---

**目前正在开发中，请勿用于生产环境。**



## 配置文件说明

具体配置请参考 [这里](https://github.com/pymumu/smartdns#%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6%E8%AF%B4%E6%98%8E)

## 构建

打开的你的命令行界面,执行如下命令:

```shell
git clone https://github.com/mokeyish/smartdns-rs.git
cd smartdns-rs
cargo build --release
```

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
