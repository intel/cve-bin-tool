# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "lz4", "version": "1.9.4", "version_strings": ["lz4-1.9.4"]},
    {
        "product": "lz4",
        "version": "1.9.3",
        "version_strings": ["1.9.3\nUnspecified error code\nOK_NoError"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "lz4-1.9.4-1.2.aarch64.rpm",
        "product": "lz4",
        "version": "1.9.4",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/tumbleweed/repo/oss/i586/",
        "package_name": "liblz4-1-1.9.4-1.2.i586.rpm",
        "product": "lz4",
        "version": "1.9.4",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/lz4/",
        "package_name": "liblz4-1_1.8.3-1+deb10u1_mips64el.deb",
        "product": "lz4",
        "version": "1.8.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/lz4/",
        "package_name": "liblz4-1_1.9.3-2_amd64.deb",
        "product": "lz4",
        "version": "1.9.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "liblz4-1_1.9.2-4_x86_64.ipk",
        "product": "lz4",
        "version": "1.9.2",
    },
]
