# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "lxc",
        "version": "2.1.1",
        "version_strings": ["2.1.1\n%s%s\nlxc.lxcpath"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "lxc-4.0.12-3.1.aarch64.rpm",
        "product": "lxc",
        "version": "4.0.12",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "lxc-4.0.12-3.1.armv6hl.rpm",
        "product": "lxc",
        "version": "4.0.12",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/lxc/",
        "package_name": "liblxc-common_5.0.1-1+b1_amd64.deb",
        "product": "lxc",
        "version": "5.0.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/lxc/",
        "package_name": "liblxc-common_5.0.1-1+b1_arm64.deb",
        "product": "lxc",
        "version": "5.0.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "liblxc_2.1.1-5_x86_64.ipk",
        "product": "lxc",
        "version": "2.1.1",
    },
]
