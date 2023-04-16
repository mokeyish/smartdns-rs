# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021-2023 openwrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=smartdns-rs
PKG_VERSION:=0.6.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/mokeyish/smartdns-rs.git
PKG_SOURCE_VERSION:=c9695e6530b9494951894df05c1ac9bfaa02f083
PKG_MIRROR_HASH:=b63d485b82d6f97aebdc3f9e1affe7b4e84e81d40c0c17ae9eb81c4b2a716c5d

PKG_MAINTAINER:=Zxlhhyccc <zxlhhyccc@gmail.com>
PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_PARALLEL:=1

PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/smartdns-rs/Default
  define Package/smartdns-rs
    SECTION:=net
    CATEGORY:=Network
    SUBMENU:=Web Servers/Proxies
    TITLE:=smartdns-rust server
    URL:=https://github.com/mokeyish/smartdns-rs.git
    DEPENDS:=$$(RUST_ARCH_DEPENDS)
  endef

  define Package/smartdns-rs/description
  A cross platform local DNS server (Dnsmasq like) written in rust to obtain the fastest website IP for the best Internet experience, supports DoT, DoH.
  endef

  define Package/smartdns-rs/install
	$$(INSTALL_DIR) $$(1)/usr/sbin
	$$(INSTALL_BIN) $$(PKG_INSTALL_DIR)/bin/smartdns $$(1)/usr/sbin/

	$$(INSTALL_DIR) $$(1)/etc/init.d
	$$(INSTALL_BIN) $(CURDIR)/conf/smartdns.init $$(1)/etc/init.d/smartdns
  endef
endef

define smartdns-rs/templates
  $(foreach smartdns,smartdns,
    $(call Package/smartdns-rs/Default,smartdns)
  )
endef
$(eval $(call smartdns-rs/templates))

define Build/Compile
	$(call Build/Compile/Cargo,, smartdns)
endef

$(foreach smartdns,smartdns, \
  $(eval $(call BuildPackage,smartdns-rs)) \
)
