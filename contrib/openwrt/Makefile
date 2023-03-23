# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021-2023 openwrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=smartdns-rust
PKG_VERSION:=0.4.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/mokeyish/smartdns-rs.git
PKG_SOURCE_VERSION:=e96c4577e8cff1ff810e96e93eb7dba9bbd25353
PKG_MIRROR_HASH:=a653849bf7f6962270f73f9cb5554c1d0e2cd4afd05764e5c9de1d860e8bb405

PKG_MAINTAINER:=Zxlhhyccc <zxlhhyccc@gmail.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1

PKG_BUILD_DEPENDS:=rust/host

RUST_PKG:=smartdns

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/smartdns-rust
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=smartdns-rust server
    URL:=https://github.com/mokeyish/smartdns-rs.git
    DEPENDS:=$$(RUST_ARCH_DEPENDS)
endef

define Package/smartdns-rust/description
  A cross platform local DNS server (Dnsmasq like) written in rust to obtain the fastest website IP for the best Internet experience, supports DoT, DoH.
endef

define Package/smartdns-rust/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(RUSTC_TARGET_ARCH)/stripped/smartdns $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/conf/smartdns.init $(1)/etc/init.d/smartdns
endef

$(eval $(call BuildPackage,smartdns-rust))
