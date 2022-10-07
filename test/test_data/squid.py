# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "squid", "version": "5.7", "version_strings": ["squid/5.7"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "squid-5.7-2.1.aarch64.rpm",
        "product": "squid",
        "version": "5.7",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "squid-5.7-2.1.armv6hl.rpm",
        "product": "squid",
        "version": "5.7",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/squid/",
        "package_name": "squid_4.11-2~bpo10+1_amd64.deb",
        "product": "squid",
        "version": "4.11",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/squid/",
        "package_name": "squid_4.11-2~bpo10+1_arm64.deb",
        "product": "squid",
        "version": "4.11",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-21.02/x86_64/packages/",
        "package_name": "squid_4.17-1_x86_64.ipk",
        "product": "squid",
        "version": "4.17",
    },
]
