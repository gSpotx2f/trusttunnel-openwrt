#
# (с) 2026 gSpot (https://github.com/gSpotx2f/trusttunnel-openwrt)
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-proto-trusttunnel
PKG_VERSION:=0.1.0
PKG_RELEASE:=2
LUCI_TITLE:=LuCI support for TrustTunnel VPN client
LUCI_DEPENDS:= +luci-base +trusttunnel-netifd-script
LUCI_PKGARCH:=all

PKG_LICENSE:=Apache-2.0

#include ../../luci.mk
include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
