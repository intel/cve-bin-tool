# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "wolfssl", "version": "4.6.0", "version_strings": ["wolfSSL 4.6.0"]}
]
package_test_data = [
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/w/wolfssl/",
        "package_name": "libwolfssl24_4.6.0+p1-0+deb11u1_amd64.deb",
        "product": "wolfssl",
        "version": "4.6.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/w/wolfssl/",
        "package_name": "libwolfssl24_4.6.0+p1-0+deb11u1_arm64.deb",
        "product": "wolfssl",
        "version": "4.6.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libwolfssl32_5.2.0-stable-1_x86_64.ipk",
        "product": "wolfssl",
        "version": "5.2.0",
    },
]
