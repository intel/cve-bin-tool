# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "i2pd", "version": "2.42.1", "version_strings": ["i2pd v\r\n2.42.1"]},
    {"product": "i2pd", "version": "2.24.0", "version_strings": ["i2pd\r\n2.24.0"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "i2pd-2.42.1-1.4.aarch64.rpm",
        "product": "i2pd",
        "version": "2.42.1",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "i2pd-2.42.1-1.4.armv6hl.rpm",
        "product": "i2pd",
        "version": "2.42.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/i2pd/",
        "package_name": "i2pd_2.23.0-1_amd64.deb",
        "product": "i2pd",
        "version": "2.23.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/i2pd/",
        "package_name": "i2pd_2.23.0-1_arm64.deb",
        "product": "i2pd",
        "version": "2.23.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "i2pd_2.24.0-1_x86_64.ipk",
        "product": "i2pd",
        "version": "2.24.0",
    },
]
