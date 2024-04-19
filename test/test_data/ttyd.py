# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "ttyd", "version": "1.6.3", "version_strings": ["1.6.3\nttyd"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "ttyd-1.7.4-1.3.aarch64.rpm",
        "product": "ttyd",
        "version": "1.7.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/ttyd/",
        "package_name": "ttyd_1.6.3-3~bpo11+1_amd64.deb",
        "product": "ttyd",
        "version": "1.6.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "ttyd_1.5.2-2_x86_64.ipk",
        "product": "ttyd",
        "version": "1.5.2",
    },
]
