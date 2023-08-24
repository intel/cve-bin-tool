# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gzip",
        "version": "1.10",
        "version_strings": ["file size changed while zipping\n1.10"],
    },
    {
        "product": "gzip",
        "version": "1.10",
        "version_strings": ["Written by Jean-loup Gailly.\n1.10"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/i586/tumbleweed/repo/oss/i586/",
        "package_name": "gzip-1.12-3.6.i586.rpm",
        "product": "gzip",
        "version": "1.12",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gzip/",
        "package_name": "gzip_1.9-3+deb10u1_amd64.deb",
        "product": "gzip",
        "version": "1.9",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "gzip_1.10-2_x86_64.ipk",
        "product": "gzip",
        "version": "1.10",
    },
]
