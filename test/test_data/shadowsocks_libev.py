# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "shadowsocks-libev",
        "version": "3.3.5",
        "version_strings": ["3.3.5\nshadowsocks-libev"],
    },
    {
        "product": "shadowsocks-libev",
        "version": "2.6.3",
        "version_strings": ["2.6.3\n  usage:\n    ss-local"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "shadowsocks-libev-3.3.5-2.6.aarch64.rpm",
        "product": "shadowsocks-libev",
        "version": "3.3.5",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "shadowsocks-libev-3.3.5-2.6.armv6hl.rpm",
        "product": "shadowsocks-libev",
        "version": "3.3.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/shadowsocks-libev/",
        "package_name": "libshadowsocks-libev2_2.6.3+ds-3+deb9u1_amd64.deb",
        "product": "shadowsocks-libev",
        "version": "2.6.3",
        "other_products": ["mbed_tls"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/shadowsocks-libev/",
        "package_name": "libshadowsocks-libev2_2.6.3+ds-3+deb9u1_arm64.deb",
        "product": "shadowsocks-libev",
        "version": "2.6.3",
        "other_products": ["mbed_tls"],
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "shadowsocks-libev-ss-redir_3.2.5-5_x86_64.ipk",
        "product": "shadowsocks-libev",
        "version": "3.2.5",
    },
]
