BOXCTL_PACKAGE_DIR:=$(realpath $(dir $(lastword $(MAKEFILE_LIST))))
BOXCTL_LEGAL_DIR?=$(abspath $(BOXCTL_PACKAGE_DIR)/../..)

include $(TOPDIR)/rules.mk

PKG_NAME:=boxctl
PKG_VERSION:=$(if $(BOXCTL_VERSION),$(BOXCTL_VERSION),dev)
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=boxctl maintainers

include $(INCLUDE_DIR)/package.mk

BOXCTL_RUNTIME_DEPENDS:=+ca-bundle +dnsmasq +firewall4 +ip-full +kmod-inet-diag +kmod-nft-tproxy +kmod-tun +nftables-json +procd +ubus +uci
BOXCTL_RUNTIME_EXTRA_DEPENDS:=ca-bundle (>=0), dnsmasq (>=0), firewall4 (>=0), ip-full (>=0), kmod-inet-diag (>=0), kmod-nft-tproxy (>=0), kmod-tun (>=0), nftables-json (>=0), procd (>=0), ubus (>=0), uci (>=0)

ifeq ($(BOXCTL_PREBUILT),1)
  BOXCTL_PACKAGE_DEPENDS:=
  BOXCTL_PACKAGE_EXTRA_DEPENDS:=$(BOXCTL_RUNTIME_EXTRA_DEPENDS)
else
  BOXCTL_PACKAGE_DEPENDS:=$(BOXCTL_RUNTIME_DEPENDS)
  BOXCTL_PACKAGE_EXTRA_DEPENDS:=
endif

define Package/boxctl
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OpenWrt selective-routing manager
  URL:=https://github.com/kontsevoye/boxctl
  DEPENDS:=$(BOXCTL_PACKAGE_DEPENDS)
  EXTRA_DEPENDS:=$(BOXCTL_PACKAGE_EXTRA_DEPENDS)
endef

define Package/boxctl/description
 boxctl manages supported proxy cores, nftables rules, policy routing, DNS,
 engine-native profiles, and its web interface on OpenWrt.
endef

define Package/boxctl/conffiles
/etc/config/boxctl
endef

define Build/Compile
endef

define Package/boxctl/preinst
#!/bin/sh
set -eu

root="$${IPKG_INSTROOT:-}/opt/boxctl"
fresh=0
[ -e "$${root}/bin/boxctl" ] || fresh=1

mkdir -p \
	"$${root}/bin" \
	"$${root}/engines/mihomo" \
	"$${root}/engines/sing-box" \
	"$${root}/.boxctl" \
	"$${root}/configs" \
	"$${root}/local-rules" \
	"$${root}/rule-providers" \
	"$${root}/proxy-providers" \
	"$${root}/subscriptions" \
	"$${root}/.install"
chmod 0700 "$${root}" "$${root}/.boxctl" "$${root}/.install"

if [ "$${fresh}" = 1 ]; then
	: > "$${root}/.install/start-stopped-until-first-success"
	chmod 0600 "$${root}/.install/start-stopped-until-first-success"
fi
endef

define Package/boxctl/install
	$(INSTALL_DIR) \
		$(1)/opt/boxctl/bin \
		$(1)/opt/boxctl/engines/mihomo \
		$(1)/opt/boxctl/engines/sing-box \
		$(1)/opt/boxctl/.boxctl \
		$(1)/opt/boxctl/configs \
		$(1)/opt/boxctl/local-rules \
		$(1)/opt/boxctl/rule-providers \
		$(1)/opt/boxctl/proxy-providers \
		$(1)/opt/boxctl/subscriptions \
		$(1)/opt/boxctl/.install
	chmod 0700 $(1)/opt/boxctl $(1)/opt/boxctl/.boxctl $(1)/opt/boxctl/.install
	$(INSTALL_BIN) $(BOXCTL_BINARY) $(1)/opt/boxctl/bin/boxctl

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/boxctl $(1)/etc/init.d/boxctl
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/boxctl $(1)/etc/config/boxctl

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/etc/hotplug.d/iface/40-boxctl $(1)/etc/hotplug.d/iface/40-boxctl

	$(INSTALL_DIR) $(1)/etc/hotplug.d/net
	$(INSTALL_BIN) ./files/etc/hotplug.d/net/99-boxctl-tun $(1)/etc/hotplug.d/net/99-boxctl-tun

	$(INSTALL_DIR) $(1)/etc/apk/protected_paths.d
	$(INSTALL_DATA) ./files/etc/apk/protected_paths.d/boxctl.list $(1)/etc/apk/protected_paths.d/boxctl.list

	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/boxctl $(1)/lib/upgrade/keep.d/boxctl

	$(INSTALL_DIR) $(1)/usr/share/licenses/boxctl
	$(INSTALL_DATA) $(BOXCTL_LEGAL_DIR)/LICENSE $(1)/usr/share/licenses/boxctl/LICENSE
endef

$(eval $(call BuildPackage,boxctl))
