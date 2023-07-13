# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "f2fs-tools",
        "version": "1.4.0",
        "version_strings": ["F2FS-tools: mkfs.f2fs Ver: %s (%s)\n2014-09-18\n1.4.0"],
    },
    {
        "product": "f2fs-tools",
        "version": "1.14.0",
        "version_strings": ["1.14.0\nUsage: fsck.f2fs"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "f2fs-tools-1.15.0-2.1.aarch64.rpm",
        "product": "f2fs-tools",
        "version": "1.15.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/f2fs-tools/",
        "package_name": "f2fs-tools_1.4.0-2_amd64.deb",
        "product": "f2fs-tools",
        "version": "1.4.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/f2fs-tools/",
        "package_name": "f2fs-tools_1.15.0-1_amd64.deb",
        "product": "f2fs-tools",
        "version": "1.15.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/x86_64/base/",
        "package_name": "f2fsck_1.14.0-3_x86_64.ipk",
        "product": "f2fs-tools",
        "version": "1.14.0",
    },
]
