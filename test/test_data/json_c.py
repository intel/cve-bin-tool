# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "json-c", "version": "0.15", "version_strings": ["0.15\njson-c"]},
    {
        "product": "json-c",
        "version": "0.12.1",
        "version_strings": [
            "0.12.1\n\\u00%c00%c\n-Infinity\n%.17g\n.+-eE\n, json_tokener_error"
        ],
    },
    {"product": "json-c", "version": "0.13.1", "version_strings": ["json-c-0.13.1"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/j/",
        "package_name": "json-c-0.16-2.fc37.aarch64.rpm",
        "product": "json-c",
        "version": "0.16",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/j/",
        "package_name": "json-c-0.16-2.fc37.i686.rpm",
        "product": "json-c",
        "version": "0.16",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/j/json-c/",
        "package_name": "libjson-c5_0.15-2_amd64.deb",
        "product": "json-c",
        "version": "0.15",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/j/json-c/",
        "package_name": "libjson-c3_0.12.1-1.1_ppc64el.deb",
        "product": "json-c",
        "version": "0.12.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libjson-c2_0.12.1-3.1_x86_64.ipk",
        "product": "json-c",
        "version": "0.12.1",
    },
]
