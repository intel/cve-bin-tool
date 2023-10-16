# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "e2fsprogs",
        "version": "1.46.5",
        "version_strings": ["e2fsprogs\n1.46.5"],
    },
    {
        "product": "e2fsprogs",
        "version": "1.46.5",
        "version_strings": ["e2fsprogs-1.46.5"],
    },
    {
        "product": "e2fsprogs",
        "version": "1.44.5",
        "version_strings": ["1.44.5\nError: ext2fs"],
    },
    {
        "product": "e2fsprogs",
        "version": "1.46.2",
        "version_strings": ["EXT2FS Library version 1.46.2"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "e2fsprogs-1.46.5-3.1.aarch64.rpm",
        "product": "e2fsprogs",
        "version": "1.46.5",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "e2fsprogs-1.46.5-3.1.armv6hl.rpm",
        "product": "e2fsprogs",
        "version": "1.46.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/e/e2fsprogs/",
        "package_name": "e2fsprogs_1.42.12-2+b1_amd64.deb",
        "product": "e2fsprogs",
        "version": "1.42.12",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/e/e2fsprogs/",
        "package_name": "libext2fs2_1.46.2-2_arm64.deb",
        "product": "e2fsprogs",
        "version": "1.46.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "e2fsprogs_1.44.5-2_x86_64.ipk",
        "product": "e2fsprogs",
        "version": "1.44.5",
    },
]
