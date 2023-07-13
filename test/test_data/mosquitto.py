# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "mosquitto",
        "version": "2.0.15",
        "version_strings": ["2.0.15\nmosquitto"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "mosquitto-2.0.15-1.1.aarch64.rpm",
        "product": "mosquitto",
        "version": "2.0.15",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "mosquitto-2.0.15-1.1.armv6hl.rpm",
        "product": "mosquitto",
        "version": "2.0.15",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/m/mosquitto/",
        "package_name": "mosquitto_1.4.10-3+deb9u4_arm64.deb",
        "product": "mosquitto",
        "version": "1.4.10",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "mosquitto-nossl_1.6.15-1_x86_64.ipk",
        "product": "mosquitto",
        "version": "1.6.15",
    },
]
