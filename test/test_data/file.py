# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "file", "version": "5.43", "version_strings": ["5.43\nmagic file"]},
    {
        "product": "file",
        "version": "5.22",
        "version_strings": ["5.22\n%s-%s\nmagic file"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "file-5.43-1.1.aarch64.rpm",
        "product": "file",
        "version": "5.43",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "file-5.43-1.1.armv6hl.rpm",
        "product": "file",
        "version": "5.43",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/file/",
        "package_name": "file_5.22+15-2+deb8u4_amd64.deb",
        "product": "file",
        "version": "5.22",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/file/",
        "package_name": "file_5.22+15-2+deb8u4_armel.deb",
        "product": "file",
        "version": "5.22",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "file_5.38-1_x86_64.ipk",
        "product": "file",
        "version": "5.38",
    },
]
