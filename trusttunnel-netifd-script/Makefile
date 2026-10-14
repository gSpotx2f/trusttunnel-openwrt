#
# (с) 2026 gSpot (https://github.com/gSpotx2f/trusttunnel-openwrt)
#

include $(TOPDIR)/rules.mk

PKG_NAME:=trusttunnel-netifd-script
PKG_VERSION:=0.1.0
PKG_RELEASE:=3
PKG_MAINTAINER:=gSpot <https://github.com/gSpotx2f/trusttunnel-openwrt>

PKG_LICENSE:=Apache-2.0

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TrustTunnel VPN client script for netifd
  URL:=https://github.com/gSpotx2f/trusttunnel-openwrt/trusttunnel-netifd-script
  PKGARCH:=all
  DEPENDS:=+kmod-tun +resolveip
endef

define Package/$(PKG_NAME)/description
  Netifd script for integrating the TrustTunnel VPN client.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/etc/trusttunnel/
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/lib/netifd/proto/trusttunnel.sh $(1)/lib/netifd/proto/trusttunnel.sh
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/trusttunnel-wrapper $(1)/usr/bin/trusttunnel-wrapper
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/lib/upgrade/keep.d/trusttunnel $(1)/lib/upgrade/keep.d/trusttunnel
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
