# TrustTunnel VPN client support for OpenWrt.
TrustTunnel client support via the OpenWrt network interface.

**OpenWrt >= 24.10.**

**Dependences:** kmod-tun, resolveip, luci-base.

## Installation notes:
1. You need to download the official TrustTunnel client build for your router's architecture from [https://github.com/TrustTunnel/TrustTunnelClient/releases](https://github.com/TrustTunnel/TrustTunnelClient/releases).

2. Then, place the `trusttunnel_client` file in the `/usr/bin` directory (`/usr/bin/trusttunnel_client`) and run `chmod +x /usr/bin/trusttunnel_client`.

3. Install the `trusttunnel-netifd-script` and `luci-proto-trusttunnel` packages.

(!) Restarting the network service (`service network restart`) will drop all current connections and restart all network interfaces!

**OpenWrt >= 25.12:**

    apk update
    wget --no-check-certificate -O /tmp/trusttunnel-netifd-script-0.1.0-r1.apk https://github.com/gSpotx2f/packages-openwrt/raw/master/25.12/trusttunnel-netifd-script-0.1.0-r1.apk
    apk --allow-untrusted add /tmp/trusttunnel-netifd-script-0.1.0-r1.apk
    rm /tmp/trusttunnel-netifd-script-0.1.0-r1.apk
    service network restart

    wget --no-check-certificate -O /tmp/luci-proto-trusttunnel-0.1.0-r1.apk https://github.com/gSpotx2f/packages-openwrt/raw/master/25.12/luci-proto-trusttunnel-0.1.0-r1.apk
    apk --allow-untrusted add /tmp/luci-proto-trusttunnel-0.1.0-r1.apk
    rm /tmp/luci-proto-trusttunnel-0.1.0-r1.apk
    service rpcd restart

i18n-ru:

    wget --no-check-certificate -O /tmp/luci-i18n-proto-trusttunnel-ru-0.1.0-r1.apk https://github.com/gSpotx2f/packages-openwrt/raw/master/25.12/luci-i18n-proto-trusttunnel-ru-0.1.0-r1.apk
    apk --allow-untrusted add /tmp/luci-i18n-proto-trusttunnel-ru-0.1.0-r1.apk
    rm /tmp/luci-i18n-proto-trusttunnel-ru-0.1.0-r1.apk

**OpenWrt 24.10:**

    opkg update
    wget --no-check-certificate -O /tmp/trusttunnel-netifd-script_0.1.0-r1_all.ipk https://github.com/gSpotx2f/packages-openwrt/raw/master/24.10/trusttunnel-netifd-script_0.1.0-r1_all.ipk
    opkg install /tmp/trusttunnel-netifd-script_0.1.0-r1_all.ipk
    rm /tmp/trusttunnel-netifd-script_0.1.0-r1_all.ipk
    service network restart

    wget --no-check-certificate -O /tmp/luci-proto-trusttunnel_0.1.0-r1_all.ipk https://github.com/gSpotx2f/packages-openwrt/raw/master/24.10/luci-proto-trusttunnel_0.1.0-r1_all.ipk
    opkg install /tmp/luci-proto-trusttunnel_0.1.0-r1_all.ipk
    rm /tmp/luci-proto-trusttunnel_0.1.0-r1_all.ipk
    service rpcd restart

i18n-ru:

    wget --no-check-certificate -O /tmp/luci-i18n-proto-trusttunnel-ru_0.1.0-r1_all.ipk https://github.com/gSpotx2f/packages-openwrt/raw/master/24.10/luci-i18n-proto-trusttunnel-ru_0.1.0-r1_all.ipk
    opkg install /tmp/luci-i18n-proto-trusttunnel-ru_0.1.0-r1_all.ipk
    rm /tmp/luci-i18n-proto-trusttunnel-ru_0.1.0-r1_all.ipk

## Screenshots:

![](https://github.com/gSpotx2f/trusttunnel-openwrt/blob/master/screenshots/01.jpg)
![](https://github.com/gSpotx2f/trusttunnel-openwrt/blob/master/screenshots/02.jpg)
![](https://github.com/gSpotx2f/trusttunnel-openwrt/blob/master/screenshots/03.jpg)
