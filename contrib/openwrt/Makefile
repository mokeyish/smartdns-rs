# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021-2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=smartdns-rust
PKG_VERSION:=0.3.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/mokeyish/smartdns-rs.git
PKG_SOURCE_VERSION:=da2926214d3b0340fe8996dd65d3f7b570d4d1ae
PKG_MIRROR_HASH:=582386deaa354be02d20f5fad5d7dcf60ca86643a531be2c6b78935252116e1a

PKG_MAINTAINER:=Zxlhhyccc <zxlhhyccc@gmail.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1

PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/smartdns-rust/Default
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
	$$(INSTALL_DIR) $$(1)/usr/sbin
	$$(INSTALL_BIN) $$(PKG_INSTALL_DIR)/bin/smartdns $$(1)/usr/sbin/

	$$(INSTALL_DIR) $$(1)/etc/init.d $$(1)/etc/config
	$$(INSTALL_BIN) $(CURDIR)/conf/smartdns.init $$(1)/etc/init.d/smartdns
	$$(INSTALL_CONF) $(CURDIR)/conf/smartdns.conf $$(1)/etc/config/smartdns
  endef
endef

define smartdns-rust/templates
  $(foreach smartdns,smartdns,
    $(call Package/smartdns-rust/Default,$(smartdns))
  )
endef
$(eval $(call smartdns-rust/templates))

define Build/Compile
	$(call Build/Compile/Cargo,, smartdns)
endef

$(foreach smartdns,smartdns, \
  $(eval $(call BuildPackage,smartdns-rust)) \
)
