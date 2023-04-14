# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "gmp", "version": "6.1.2", "version_strings": ["gmp-6.1.2"]},
    {
        "product": "gmp",
        "version": "6.2.0",
        "version_strings": ["libgmp.so.10.4.0-6.2.0"],
    },
    {
        "product": "gmp",
        "version": "6.0.0",
        "version_strings": [
            "6.0.0\n0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        ],
    },
    {
        "product": "gmp",
        "version": "4.3.1",
        "version_strings": ["4.3.1\n0123456789abcdefghijklmnopqrstuvwxyz"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/centos-stream/9-stream/BaseOS/aarch64/os/Packages/",
        "package_name": "gmp-6.2.0-10.el9.aarch64.rpm",
        "product": "gmp",
        "version": "6.2.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gmp/",
        "package_name": "libgmp10_6.0.0+dfsg-6_amd64.deb",
        "product": "gmp",
        "version": "6.0.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gmp/",
        "package_name": "libgmp10_6.2.1+dfsg-1+deb11u1_mipsel.deb",
        "product": "gmp",
        "version": "6.2.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libgmp10_6.1.2-2_x86_64.ipk",
        "product": "gmp",
        "version": "6.1.2",
    },
]
