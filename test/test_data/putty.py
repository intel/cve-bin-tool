# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "putty", "version": "0.77", "version_strings": ["putty-0.77"]},
    {"product": "putty", "version": "0.70", "version_strings": ["PuTTY-Release-0.70"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "putty-0.77-1.3.aarch64.rpm",
        "product": "putty",
        "version": "0.77",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "putty-0.77-1.3.armv6hl.rpm",
        "product": "putty",
        "version": "0.77",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/putty/",
        "package_name": "putty_0.70-6_arm64.deb",
        "product": "putty",
        "version": "0.70",
    },
]
