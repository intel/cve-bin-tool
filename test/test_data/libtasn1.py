# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libtasn1",
        "version": "4.15.0",
        "version_strings": ["ASSIGNMENT,\n4.15.0"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libtasn1-4.19.0-2.fc38.aarch64.rpm",
        "product": "libtasn1",
        "version": "4.19.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libt/libtasn1-6/",
        "package_name": "libtasn1-6_4.13-3_arm64.deb",
        "product": "libtasn1",
        "version": "4.13",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libtasn1_4.15.0-1_x86_64.ipk",
        "product": "libtasn1",
        "version": "4.15.0",
    },
]
