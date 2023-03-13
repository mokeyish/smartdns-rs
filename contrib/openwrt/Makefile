# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017-2020 Yousong Zhou <yszhou4tech@gmail.com>
# Copyright (C) 2021-2023 openwrt.org

include $(TOPDIR)/rules.mk

PKG_NAME:=smartdns-rust
PKG_VERSION:=0.3.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/mokeyish/smartdns-rs.git
PKG_SOURCE_VERSION:=9f87f49a5e441c518afd8f7f99e048cf9675764f
PKG_MIRROR_HASH:=2117b1e7a6c1abb7c08ef10570dbcae9bfb831f8d970c9cf4d27f724b6816655

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

define Package/smartdns-rust/install
    $$(INSTALL_DIR) $$(1)/usr/sbin
    $$(INSTALL_BIN) $$(PKG_INSTALL_DIR)/bin/smartdns $$(1)/usr/sbin/
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
